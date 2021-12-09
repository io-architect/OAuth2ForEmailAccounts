package Kernel::System::OAuth;

use strict;
use warnings;
use utf8;

use LWP::Authen::OAuth2;
use MIME::Base64;

use Data::Dumper;

our @ObjectDependencies = (
    'Kernel::Config',
    'Kernel::System::DB',
    'Kernel::System::Log',
    'Kernel::System::Main',
);

sub new {
    my ( $Type, %Param ) = @_;

    # allocate new hash for object
    my $Self = {};
    bless( $Self, $Type );

    $Self->{AuthSite} = {
        'Gmail' => {
            AuthURL => 'https://accounts.google.com/o/oauth2/auth',
            TokenURL => 'https://oauth2.googleapis.com/token',
            Scope => 'https://mail.google.com/',
        },
        'Exchange' => {
            AuthURL => 'https://login.microsoftonline.com/6c36da81-4cf3-4308-939d-421322d30d5a/oauth2/v2.0/authorize',
            TokenURL => 'https://login.microsoftonline.com/6c36da81-4cf3-4308-939d-421322d30d5a/oauth2/v2.0/token',
            Scope => 'offline_access https://outlook.office365.com/POP.AccessAsUser.All https://outlook.office365.com/IMAP.AccessAsUser.All',
        },
    };

    return $Self;
}

=head2 Create()
    OAuthエントリを追加

    my $SiteID = $OAuthObject->Create(
        MailAccountID => 1,
        AuthSite => 'Gmail',           # || 'Microsoft365'
        ClientID => $ClientID,         # OAuth client id
        ClientSecret => $ClientSecret, # OAuth client secret
        UserID => 1,
    );
=cut
sub Create {
    my ($Self, %Param) = @_;

    for (qw(MailAccountID AuthSite ClientID ClientSecret UserID AuthURL TokenURL)) {
        if ( !$Param{$_} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "OAuth::Create Need $_!"
            );
            return;
        }
    }

    my $DBObject = $Kernel::OM->Get('Kernel::System::DB');
    return if $DBObject->Do(
        SQL => 'INSERT INTO oauth_token (mail_account_id, auth_site, '
            . 'client_id, client_secret, auth_url, token_url, '
            . 'create_time, create_by, change_time, change_by) VALUES '
            .'(?, ?, ?, ?, ?, ?, '
            .' current_timestamp, ?, current_timestamp, ?)',
        Bind => [
            \$Param{MailAccountID}, \$Param{AuthSite},
            \$Param{ClientID}, \$Param{ClientSecret},
            \$Param{AuthURL}, \$Param{TokenURL},
            \$Param{UserID}, \$Param{UserID},
        ],
    );
    return $Param{MailAccountID};
}

=head2 EntryGet()
OAUTHレコードの取得

    my $Entry = $Self->EntryGet(
        ID => 1,
    );
    $Entry = { ID => 1, ..}

=cut
sub EntryGet {
    my ($Self, %Param) = @_;

    for (qw(ID)) {
        if ( !$Param{$_} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "OAuth::EntryGet Need $_!"
            );
            return;
        }
    }

    my $DBObject = $Kernel::OM->Get('Kernel::System::DB');

    $DBObject->Prepare(
        SQL => "select "
            ."mail_account_id, auth_site, client_id, client_secret, "
            ."auth_url, token_url, "
            ."token_string, "
            ."create_time, create_by, change_time, change_by "
            ."from oauth_token where mail_account_id=?",
        Bind => [ \$Param{ID} ],
    );
    while (my @Row = $DBObject->FetchrowArray()) {
        return {
            ID => $Row[0], MailAccountID => $Row[0], AuthSite => $Row[1], ClientID => $Row[2], ClientSecret => $Row[3],
            AuthURL => $Row[4], TokenURL => $Row[5],
            TokenString => $Row[6],
            CreateTime => $Row[7], CreateBy => $Row[8],
            ChangeTime => $Row[9], ChangeBy => $Row[10],
        };
    }
    return;
}

=head2 EntryUpdate()
レコード更新

    $Success = $Self->EntryUpdate(
        ID => 1, # required
        AuthSite => 'Gmail'  # optional
        TokenString => 'XXX' # optional
        ClientID =>
        ClientSecret =>
        SessionID =>         # optional
        UserID => # required
    );
=cut
sub EntryUpdate {
    my ($Self, %Param) = @_;
    for (qw(ID UserID)) {
        if ( !$Param{$_} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "OAuth::EntryGet Need $_!"
            );
            return;
        }
    }
    my $ColMap = {
            AuthSite     => 'auth_site',
            TokenString  => 'token_string',
            ClientID     => 'client_id',
            ClientSecret => 'client_secret',
            SessionID    => 'session_id',
            AuthURL      => 'auth_url',
            TokenURL     => 'token_url',
    };

    my $SQL = "update oauth_token set change_time=current_timestamp, change_by=?";
    my $Bind = [\$Param{UserID}];
    for my $Parameter (qw(AuthSite TokenString ClientID ClientSecret SessionID AuthURL TokenURL)) {
        next if !defined($Param{$Parameter});
        $SQL .= ", $ColMap->{$Parameter}=?";
        push(@$Bind, \$Param{$Parameter});
    }
    $SQL .= " where mail_account_id=?";
    push(@$Bind, \$Param{ID});
    return $Kernel::OM->Get('Kernel::System::DB')->Do(
        SQL => $SQL,
        Bind => $Bind,
    );
}

=head2 EntryDelete()
    my $Success = $Self->EntryDelete(
        ID => 1,
    )
=cut
sub EntryDelete {
    my ($Self, %Param) = @_;
    if (!defined($Param{ID})) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message => "OAuth::EntryDelete Need ID!",
        );
        return;
    }

    return $Kernel::OM->Get('Kernel::System::DB')->Do(
        SQL => 'delete from oauth_token where mail_account_id=?',
        Bind => [ \$Param{ID}],
    );
}

=head2 GetIDFromSessionID()
    $ID = $Self->GetIDFromSessionID(
        SessionID => 'xxx',
    );
=cut
sub GetIDFromSessionID {
    my ($Self, %Param) = @_;

    my $DBObject = $Kernel::OM->Get('Kernel::System::DB');
    $DBObject->Prepare(
        SQL => "select mail_account_id from oauth_token where session_id=?",
        Bind => [\$Param{SessionID}],
    );
    while (my @Row = $DBObject->FetchrowArray()) {
        return $Row[0];
    }
    return;
}

=head2 GetIDFromMailAddress()
    $ID = $Self->GetIDFromMailAddress(
        MailAddress => 'xxx@gmail.com',
        Host => 'pop.xx.com:999',
    );
=cut
sub GetIDFromMailAddress {
    my ($Self, %Param) = @_;

    my $DBObject = $Kernel::OM->Get('Kernel::System::DB');
    # oauth_tokenのIDはmail_accountのIDと同一のため、mail_accountに対するクエリーで済む
    $DBObject->Prepare(
        SQL => "select id from mail_account where login=? and host=?",
        Bind => [\$Param{MailAddress}, \$Param{Host}],
    );
    while (my @Row = $DBObject->FetchrowArray()) {
        return $Row[0];
    }
    return;
}

=head2 IsOAuthType()

    my $IsOAuth = $Self->IsOAuthType(
        Type => 'IMAPGmail',
    );
=cut
sub IsOAuthType {
    my ($Self, %Param) = @_;

    if ($Param{Type} eq 'IMAPGmail' || $Param{Type} eq 'POPGmail' ||
        $Param{Type} eq 'IMAPExchange' || $Param{Type} eq 'POPExchange') {
        return 1;
    }
    return;
}

=head2 AuthTypeGet()
=cut
sub AuthTypeGet {
    my ($Self, %Param) = @_;

    if ($Param{Type} eq 'IMAPGmail' || $Param{Type} eq 'POPGmail') {
        return 'Gmail';
    }
    elsif ($Param{Type} eq 'IMAPExchange' || $Param{Type} eq 'POPExchange'){
        return 'Exchange';
    }
    else {
        return;
    }
}


=head2 AuthURLGet()
認証用URLの取得
=cut
sub AuthURLGet {
    my ($Self, %Param) = @_;

    for (qw(ID)) {
        if ( !$Param{$_} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "OAuth::EntryGet Need $_!"
            );
            return;
        }
    }

    my $TokenEntry = $Self->EntryGet(
        ID => $Param{ID},
    );

    my $oauth = $Self->_NewLWPAuthenOAuth2(
        ID => $Param{ID},
    );

    my $URL = $oauth->authorization_url();

    if ($TokenEntry->{AuthSite} eq 'Gmail') {
        # Googleの場合これしないとRefreshTokenが来ない
        $URL .= "&access_type=offline&approval_prompt=force";
    }
    return $URL;
}


=head2 RequestToken()
認証サイトから返されたCodeからトークンを生成し、レコードに保存する

    $Self->RequestToken(
        ID => 1,
        Code => 'xxxxxxx',
    );
=cut
sub RequestToken {
    my ($Self, %Param) = @_;

    for (qw(ID)) {
        if ( !$Param{$_} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "OAuth::EntryGet Need $_!"
            );
            return;
        }
    }

    my $oauth = $Self->_NewLWPAuthenOAuth2(
        ID => $Param{ID},
    );

    eval {
        $oauth->request_tokens(code => $Param{Code});
    };
    if (my $Error = $@) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message => "OAuth::RequestToken failed!: $Error",
        );
        return;
    }
    return 1;
}

=head2 Resume()
既にトークンを取得できているエントリからoauthオブジェクトを生成する

    my $oauth = $OAuthObject->Resume(
        ID => 3,
    );

=cut
sub Resume {
    my ($Self, %Param) = @_;

    for (qw(ID)) {
        if ( !$Param{$_} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "OAuth::Resume Need $_!"
            );
            return;
        }
    }

    return $Self->_NewLWPAuthenOAuth2(
            ID => $Param{ID},
            Resume => 1,
    );
}

=head2 AccessTokenGet()
    my $AccessToken = $Self->AccessTokenGet(
        ID => 1,
    );
=cut
sub AccessTokenGet {
    my ($Self, %Param) = @_;

    my $LogObject = $Kernel::OM->Get('Kernel::System::Log');

    my $oauth = $Self->_NewLWPAuthenOAuth2(
        ID => $Param{ID},
        Resume => 1,
    );
    if (!defined($oauth)) {
        $LogObject->Log(
            Priority => 'error',
            Message => "OAuth::AccessTokenGet Can't get oauth object!",
        );
        return;
    }
    if ($oauth->should_refresh) {
        if ($oauth->can_refresh_tokens) {
            $LogObject->Log(
                Priority => 'notice',
                Message => "OAuth::AccessTokenGet refresh access token",
            );
            $oauth->refresh_access_token();
        }
        else {
            $LogObject->Log(
                Priority => 'error',
                Message => "OAuth::AccessTokenGet Can't refresh token!",
            );
            return;
        }
    }

    return $oauth->access_token->{access_token};
}

=head2 AuthStringGet()
サーバに渡す認証用文字列の取得・生成
    my $AuthString = $Self->AuthStringGet(
        ID => 1,
        MailAccount => 'xx@gmail.com',
    );
=cut
sub AuthStringGet {
    my ($Self, %Param) = @_;

    for (qw(ID MailAccount)) {
        if ( !$Param{$_} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "OAuth::AuthString Need $_!"
            );
            return;
        }
    }

    my $Token = $Self->AccessTokenGet(
        ID => $Param{ID},
    );
    if (!defined($Token)) {
        return;
    }
    my $AuthStrPlain = sprintf("user=%s%cauth=Bearer %s%c%c", $Param{MailAccount}, 1, $Token, 1, 1);
    my $AuthStr = encode_base64($AuthStrPlain, '');
    return $AuthStr;
}

=head2 SessionDataReset()
oauth_token TBLに保持している全てのセッションID情報をリセットする
    $Self->SessionDataReset();
=cut
sub SessionDataReset {
    my ($Self, %Param) = @_;

    my $DBObject = $Kernel::OM->Get('Kernel::System::DB');
    $DBObject->Do(
        SQL => "update oauth_token set session_id=NULL"
    );
}

=head3 _NewLWPAuthenOAuth2()
oauthオブジェクトの取得

    my $oauth = $Self->_NewLWPAuthenOAuth2(
        ID => 1,
        Resume => 1, # optional
    );

=cut
sub _NewLWPAuthenOAuth2 {
    my ($Self, %Param) = @_;

    my $LogObject = $Kernel::OM->Get('Kernel::System::Log');

    my $TokenEntry = $Self->EntryGet(
        ID => $Param{ID},
    );
    if (!defined($TokenEntry)) {
        $LogObject->Log(
            Priority => 'error',
            Message => "OAuth::_NewLWPAuthenOAuth2 Can't get OAUTH entry(ID=$Param{ID})",
        );
        return;
    }

    my $AuthURL = $TokenEntry->{AuthURL};
    my $TokenURL = $TokenEntry->{TokenURL};
    my $Scope = $Self->{AuthSite}->{$TokenEntry->{AuthSite}}->{Scope};
    my $ClientID = $TokenEntry->{ClientID};
    my $ClientSecret = $TokenEntry->{ClientSecret};

    my $Domain = $Kernel::OM->Get('Kernel::Config')->Get('FQDN');
    my $Path = $Kernel::OM->Get('Kernel::Config')->Get('ScriptAlias');
    $Path =~ s/\/+$//;

    my $RedirectURI = "https://$Domain/$Path/accesstoken.pl";

    my %OAuthParam = (
        authorization_endpoint => $AuthURL,
        token_endpoint  => $TokenURL,
        client_id => $ClientID,
        client_secret => $ClientSecret,
        redirect_uri => $RedirectURI,
        scope => $Scope,
        save_tokens => \&_SaveTokens,
        save_tokens_args => [$Param{ID}],
    );

    if ($Param{Resume}) {
        if (!$TokenEntry->{TokenString}) {
            $LogObject->Log(
                Priority => 'error',
                Message => "OAuth::_NewLWPAuthenOAuth2: Resume requested, but TokenString is not exists!",
            );
            return;
        }
        $OAuthParam{token_string} = $TokenEntry->{TokenString};
    }

    my $oauth = LWP::Authen::OAuth2->new(
        %OAuthParam,
    );

    return $oauth;
}


=head3 _SaveTokens()
トークン保存のコールバック
=cut
sub _SaveTokens {
    my ($TokenString, $ID) = @_;
    my $OAuthObject = $Kernel::OM->Get('Kernel::System::OAuth');
    $OAuthObject->EntryUpdate(
        ID => $ID,
        TokenString => $TokenString,
        UserID => 1,
    )
}


1;
