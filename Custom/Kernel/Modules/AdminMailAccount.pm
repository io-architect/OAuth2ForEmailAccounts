# --
# OTOBO is a web-based ticketing system for service organisations.
# --
# Copyright (C) 2001-2020 OTRS AG, https://otrs.com/
# Copyright (C) 2019-2021 Rother OSS GmbH, https://otobo.de/
# --
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later version.
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
# --

package Kernel::Modules::AdminMailAccount;

use strict;
use warnings;

use Data::Dumper;

use Kernel::Language qw(Translatable);

our $ObjectManagerDisabled = 1;

sub new {
    my ( $Type, %Param ) = @_;

    # allocate new hash for object
    my $Self = {%Param};
    bless( $Self, $Type );

    return $Self;
}

sub Run {
    my ( $Self, %Param ) = @_;

    my $LayoutObject = $Kernel::OM->Get('Kernel::Output::HTML::Layout');
    my $ParamObject  = $Kernel::OM->Get('Kernel::System::Web::Request');
    my $MailAccount  = $Kernel::OM->Get('Kernel::System::MailAccount');

    my %GetParam = ();
    my @Params   = (
        qw(ID Login Password Host Type TypeAdd Comment ValidID QueueID IMAPFolder Trusted DispatchingBy )
### OAUTH
        , qw(ClientID ClientSecret AuthURL TokenURL)
### OAUTH End
    );
    for my $Parameter (@Params) {
        $GetParam{$Parameter} = $ParamObject->GetParam( Param => $Parameter );
    }
    # ------------------------------------------------------------ #
    # Run
    # ------------------------------------------------------------ #
    if ( $Self->{Subaction} eq 'Run' ) {

        # challenge token check for write action
        $LayoutObject->ChallengeTokenCheck();

        # Lock process with PID to prevent race conditions with console command
        # Maint::PostMaster::MailAccountFetch executed by the OTOBO daemon or manually.
        # Please see bug#13235
        my $PIDObject = $Kernel::OM->Get('Kernel::System::PID');

        my $PIDCreated = $PIDObject->PIDCreate(
            Name => 'MailAccountFetch',
            TTL  => 600,                  # 10 minutes
        );

        if ( !$PIDCreated ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Unable to register the process in the database. Is another instance still running?"
            );
            return $LayoutObject->Redirect( OP => 'Action=AdminMailAccount;Locked=1' );
        }

        my %Data = $MailAccount->MailAccountGet(%GetParam);
        if ( !%Data ) {

            $PIDObject->PIDDelete( Name => 'MailAccountFetch' );
            return $LayoutObject->ErrorScreen();
        }

        my $Ok = $MailAccount->MailAccountFetch(
            %Data,
            Limit  => 15,
            UserID => $Self->{UserID},
        );

        $PIDObject->PIDDelete( Name => 'MailAccountFetch' );

        if ( !$Ok ) {
            return $LayoutObject->ErrorScreen();
        }
        return $LayoutObject->Redirect( OP => 'Action=AdminMailAccount;Ok=1' );
    }

    # ------------------------------------------------------------ #
    # delete
    # ------------------------------------------------------------ #
    elsif ( $Self->{Subaction} eq 'Delete' ) {

        # challenge token check for write action
        $LayoutObject->ChallengeTokenCheck();

        my $Delete = $MailAccount->MailAccountDelete(%GetParam);
        if ( !$Delete ) {
            return $LayoutObject->ErrorScreen();
        }
        return $LayoutObject->Attachment(
            ContentType => 'text/html',
            Content     => $Delete,
            Type        => 'inline',
            NoCache     => 1,
        );
    }

    # ------------------------------------------------------------ #
    # add new mail account
    # ------------------------------------------------------------ #
    elsif ( $Self->{Subaction} eq 'AddNew' ) {
        my $Output = $LayoutObject->Header();
        $Output .= $LayoutObject->NavigationBar();
        $Self->_MaskAddMailAccount(
            Action => 'AddNew',
            %GetParam,
        );
        $Output .= $LayoutObject->Output(
            TemplateFile => 'AdminMailAccount',
            Data         => \%Param,
        );
        $Output .= $LayoutObject->Footer();
        return $Output;
    }

    # ------------------------------------------------------------ #
    # add action
    # ------------------------------------------------------------ #
    elsif ( $Self->{Subaction} eq 'AddAction' ) {

        # challenge token check for write action
        $LayoutObject->ChallengeTokenCheck();
        my %Errors;

        # check needed data
        for my $Needed (qw(Login Password Host)) {
            if ( !$GetParam{$Needed} ) {
                $Errors{ $Needed . 'AddInvalid' } = 'ServerError';
            }
        }
        for my $Needed (qw(TypeAdd ValidID)) {
            if ( !$GetParam{$Needed} ) {
                $Errors{ $Needed . 'Invalid' } = 'ServerError';
            }
        }

        # if no errors occurred
        if ( !%Errors ) {

            # add mail account
            my $ID = $MailAccount->MailAccountAdd(
                %GetParam,
                Type   => $GetParam{'TypeAdd'},
                UserID => $Self->{UserID},
            );
### OAUTH
            if ($ID) {
                if ($GetParam{'TypeAdd'} eq 'IMAPGmail' ||
                     $GetParam{'TypeAdd'} eq 'POPGmail') {
                    my $Success = $Kernel::OM->Get('Kernel::System::OAuth')->Create(
                        MailAccountID => $ID,
                        AuthSite => 'Gmail',           # || 'Microsoft365'
                        %GetParam,
                        UserID => $Self->{UserID},
                    );
                }
                elsif ($GetParam{'TypeAdd'} eq 'IMAPExchange' ||
                    $GetParam{'TypeAdd'} eq 'POPExchange') {
                    my $Success = $Kernel::OM->Get('Kernel::System::OAuth')->Create(
                        MailAccountID => $ID,
                        AuthSite => 'Exchange',           # || 'Microsoft365'
                        %GetParam,
                        UserID => $Self->{UserID},
                    );
                }
            }
###
            if ($ID) {
                $Self->_Overview();
                my $Output = $LayoutObject->Header();
                $Output .= $LayoutObject->NavigationBar();
                $Output .= $LayoutObject->Notify( Info => Translatable('Mail account added!') );
                $Output .= $LayoutObject->Output(
                    TemplateFile => 'AdminMailAccount',
                    Data         => \%Param,
                );
                $Output .= $LayoutObject->Footer();
                return $Output;
            }
        }

        # something has gone wrong
        my $Output = $LayoutObject->Header();
        $Output .= $LayoutObject->NavigationBar();
        $Output .= $LayoutObject->Notify( Priority => 'Error' );
        $Self->_MaskAddMailAccount(
            Action => 'AddNew',
            Errors => \%Errors,
            %GetParam,
        );
        $Output .= $LayoutObject->Output(
            TemplateFile => 'AdminMailAccount',
            Data         => \%Param,
        );
        $Output .= $LayoutObject->Footer();
        return $Output;
    }

    # ------------------------------------------------------------ #
    # update
    # ------------------------------------------------------------ #
    elsif ( $Self->{Subaction} eq 'Update' ) {
        my %Data   = $MailAccount->MailAccountGet(%GetParam);
### OAuth
        my $OAuthData = $Kernel::OM->Get('Kernel::System::OAuth')->EntryGet(
            ID => $GetParam{ID},
        );
### OAuth END
        my $Output = $LayoutObject->Header();
        $Output .= $LayoutObject->NavigationBar();
        $Self->_MaskUpdateMailAccount(
            Action => 'Update',
            %Data,
### OAuth
            %$OAuthData,
### OAuth END
        );
        $Output .= $LayoutObject->Output(
            TemplateFile => 'AdminMailAccount',
            Data         => \%Param,
        );
        $Output .= $LayoutObject->Footer();
        return $Output;
    }

    # ------------------------------------------------------------ #
    # update action
    # ------------------------------------------------------------ #
    elsif ( $Self->{Subaction} eq 'UpdateAction' ) {

        # challenge token check for write action
        $LayoutObject->ChallengeTokenCheck();

        my %Errors;

        # check needed data
        for my $Needed (qw(Login Password Host)) {
            if ( !$GetParam{$Needed} ) {
                $Errors{ $Needed . 'EditInvalid' } = 'ServerError';
            }
        }
        for my $Needed (qw(Type ValidID DispatchingBy QueueID)) {
            if ( !$GetParam{$Needed} ) {
                $Errors{ $Needed . 'Invalid' } = 'ServerError';
            }
        }
        if ( !$GetParam{Trusted} ) {
            $Errors{TrustedInvalid} = 'ServerError' if ( $GetParam{Trusted} != 0 );
        }

        # if no errors occurred
        if ( !%Errors ) {

            if ( $GetParam{Password} eq 'otobo-dummy-password-placeholder' ) {
                my %OriginalData = $MailAccount->MailAccountGet(%GetParam);
                $GetParam{Password} = $OriginalData{Password};
            }
### OAUTH
            my $OAuthObject = $Kernel::OM->Get('Kernel::System::OAuth');
            my $OAuthEntry = $OAuthObject->EntryGet(
                ID => $GetParam{ID},
            );
            if ($OAuthEntry && !$OAuthObject->IsOAuthType(Type => $GetParam{Type})) {
                # エントリがあってOAUTHじゃなくなった→削除
                $OAuthObject->EntryDelete(
                    ID => $GetParam{ID},
                );
            }
            elsif (!$OAuthEntry && $OAuthObject->IsOAuthType(Type => $GetParam{Type})) {
                # エントリなしからOAUTHになった → 作成
                $OAuthObject->Create(
                    MailAccountID => $GetParam{ID},
                    AuthSite => $OAuthObject->AuthTypeGet( Type => $GetParam{Type} ),
                    UserID => $Self->{UserID},
                    %GetParam,
                );
            }
            elsif ($OAuthEntry && $OAuthObject->IsOAuthType(Type => $GetParam{Type})) {
                # エントリあり, OAUTH対象 → 更新
                $OAuthObject->EntryUpdate(
                    UserID => $Self->{UserID},
                    %GetParam,
                );
            }

### OAUTH END
            # update mail account
            my $Update = $MailAccount->MailAccountUpdate(
                %GetParam,
                UserID => $Self->{UserID},
            );
            if ($Update) {

                # if the user would like to continue editing the mail account just redirect to the edit screen
                if (
                    defined $ParamObject->GetParam( Param => 'ContinueAfterSave' )
                    && ( $ParamObject->GetParam( Param => 'ContinueAfterSave' ) eq '1' )
                    )
                {
                    my $ID = $ParamObject->GetParam( Param => 'ID' ) || '';
                    return $LayoutObject->Redirect(
                        OP => "Action=$Self->{Action};Subaction=Update;ID=$ID"
                    );
                }
                else {

                    # otherwise return to overview
                    return $LayoutObject->Redirect( OP => "Action=$Self->{Action}" );
                }
            }
        }

        # something has gone wrong
        my $Output = $LayoutObject->Header();
        $Output .= $LayoutObject->NavigationBar();
        $Output .= $LayoutObject->Notify( Priority => 'Error' );
        $Self->_MaskUpdateMailAccount(
            Action => 'Update',
            Errors => \%Errors,
            %GetParam,
        );
        $Output .= $LayoutObject->Output(
            TemplateFile => 'AdminMailAccount',
            Data         => \%Param,
        );
        $Output .= $LayoutObject->Footer();
        return $Output;
    }
###
    elsif ($Self->{Subaction} eq 'AuthOAuthToken') {
        return $Self->_AuthOAuthToken(
            LayoutObject => $LayoutObject,
            ParamObject => $ParamObject,
            %Param);
    }
    elsif ($Self->{Subaction} eq 'AccessCode' || defined($ParamObject->GetParam(Param => 'Subaction=AccessCode'))) {
        return $Self->_AccessCode(
            LayoutObject => $LayoutObject,
            ParamObject => $ParamObject,
        );
    }
###
    # ------------------------------------------------------------ #
    # overview
    # ------------------------------------------------------------ #
    else {
### OAuth
        # 一覧画面表示時点で紐付け用のセッションIDをクリアする
        $Kernel::OM->Get('Kernel::System::OAuth')->SessionDataReset();
### OAuth END

        $Self->_Overview();

        my $Ok     = $ParamObject->GetParam( Param => 'Ok' );
        my $Locked = $ParamObject->GetParam( Param => 'Locked' );

        my $Output = $LayoutObject->Header();
        $Output .= $LayoutObject->NavigationBar();

        if ($Ok) {
            $Output .= $LayoutObject->Notify( Info => Translatable('Finished') );
        }
        if ($Locked) {
            $Output .= $LayoutObject->Notify(
                Info => Translatable('Email account fetch already fetched by another process. Please try again later!'),
            );
        }

        $Output .= $LayoutObject->Output(
            TemplateFile => 'AdminMailAccount',
            Data         => \%Param,
        );
        $Output .= $LayoutObject->Footer();
        return $Output;
    }
}

sub _Overview {
    my ( $Self, %Param ) = @_;

    my $LayoutObject = $Kernel::OM->Get('Kernel::Output::HTML::Layout');
    my $MailAccount  = $Kernel::OM->Get('Kernel::System::MailAccount');

    my %Backend = $MailAccount->MailAccountBackendList();

    $LayoutObject->Block(
        Name => 'Overview',
        Data => \%Param,
    );

    $LayoutObject->Block( Name => 'ActionList' );
    $LayoutObject->Block( Name => 'ActionAdd' );
    $LayoutObject->Block( Name => 'Filter' );

    $LayoutObject->Block(
        Name => 'OverviewResult',
        Data => \%Param,
    );

    my %List = $MailAccount->MailAccountList( Valid => 0 );

    # if there are any mail accounts, they are shown
    if (%List) {
        for my $ListKey ( sort { $List{$a} cmp $List{$b} } keys %List ) {
            my %Data = $MailAccount->MailAccountGet( ID => $ListKey );
            if ( !$Backend{ $Data{Type} } ) {
                $Data{Type} .= '(not installed!)';
            }

            my @List = $Kernel::OM->Get('Kernel::System::Valid')->ValidIDsGet();
            $Data{ShownValid} = $Kernel::OM->Get('Kernel::System::Valid')->ValidLookup(
                ValidID => $Data{ValidID},
            );

            $LayoutObject->Block(
                Name => 'OverviewResultRow',
                Data => \%Data,
            );
        }
    }

    # otherwise a no data found msg is displayed
    else {
        $LayoutObject->Block(
            Name => 'NoDataFoundMsg',
            Data => {},
        );
    }
    return 1;
}

sub _MaskUpdateMailAccount {
    my ( $Self, %Param ) = @_;
open(DBGLOG, ">>/tmp/dbg.log");
print DBGLOG Dumper(\%Param);
close(DBGLOG);

    my $LayoutObject = $Kernel::OM->Get('Kernel::Output::HTML::Layout');

    # get valid list
    my %ValidList        = $Kernel::OM->Get('Kernel::System::Valid')->ValidList();
    my %ValidListReverse = reverse %ValidList;

    # build ValidID string
    $Param{ValidOption} = $LayoutObject->BuildSelection(
        Data       => \%ValidList,
        Name       => 'ValidID',
        SelectedID => $Param{ValidID} || $ValidListReverse{valid},
        Class      => 'Modernize Validate_Required ' . ( $Param{Errors}->{'ValidIDInvalid'} || '' ),
    );

    $Param{TypeOption} = $LayoutObject->BuildSelection(
        Data       => { $Kernel::OM->Get('Kernel::System::MailAccount')->MailAccountBackendList() },
        Name       => 'Type',
        SelectedID => $Param{Type} || $Param{TypeAdd} || '',
        Class      => 'Modernize Validate_Required ' . ( $Param{Errors}->{'TypeInvalid'} || '' ),
    );

    $Param{TrustedOption} = $LayoutObject->BuildSelection(
        Data       => $Kernel::OM->Get('Kernel::Config')->Get('YesNoOptions'),
        Name       => 'Trusted',
        SelectedID => $Param{Trusted} || 0,
        Class      => 'Modernize ' . ( $Param{Errors}->{'TrustedInvalid'} || '' ),
    );

    $Param{DispatchingOption} = $LayoutObject->BuildSelection(
        Data => {
            From  => Translatable('Dispatching by email To: field.'),
            Queue => Translatable('Dispatching by selected Queue.'),
        },
        Name       => 'DispatchingBy',
        SelectedID => $Param{DispatchingBy},
        Class      => 'Modernize Validate_Required ' . ( $Param{Errors}->{'DispatchingByInvalid'} || '' ),
    );

    $Param{QueueOption} = $LayoutObject->AgentQueueListOption(
        Data           => { $Kernel::OM->Get('Kernel::System::Queue')->QueueList( Valid => 1 ) },
        Name           => 'QueueID',
        SelectedID     => $Param{QueueID},
        OnChangeSubmit => 0,
        Class          => 'Modernize Validate_Required ' . ( $Param{Errors}->{'QueueIDInvalid'} || '' ),
    );
    $LayoutObject->Block(
        Name => 'Overview',
        Data => { %Param, },
    );
    $LayoutObject->Block(
        Name => 'ActionList',
    );
    $LayoutObject->Block(
        Name => 'ActionOverview',
    );
    $LayoutObject->Block(
        Name => 'OverviewUpdate',
        Data => {
            %Param,
            %{ $Param{Errors} },
        },
    );

    return 1;
}

sub _MaskAddMailAccount {
    my ( $Self, %Param ) = @_;

    my $LayoutObject = $Kernel::OM->Get('Kernel::Output::HTML::Layout');

    # get valid list
    my %ValidList        = $Kernel::OM->Get('Kernel::System::Valid')->ValidList();
    my %ValidListReverse = reverse %ValidList;

    # build ValidID string
    $Param{ValidOption} = $LayoutObject->BuildSelection(
        Data       => \%ValidList,
        Name       => 'ValidID',
        SelectedID => $Param{ValidID} || $ValidListReverse{valid},
        Class      => 'Modernize Validate_Required ' . ( $Param{Errors}->{'ValidIDInvalid'} || '' ),
    );

    $Param{TypeOptionAdd} = $LayoutObject->BuildSelection(
        Data       => { $Kernel::OM->Get('Kernel::System::MailAccount')->MailAccountBackendList() },
        Name       => 'TypeAdd',
        SelectedID => $Param{Type} || $Param{TypeAdd} || '',
        Class      => 'Modernize Validate_Required ' . ( $Param{Errors}->{'TypeAddInvalid'} || '' ),
    );

    $Param{TrustedOption} = $LayoutObject->BuildSelection(
        Data       => $Kernel::OM->Get('Kernel::Config')->Get('YesNoOptions'),
        Name       => 'Trusted',
        Class      => 'Modernize ' . ( $Param{Errors}->{'TrustedInvalid'} || '' ),
        SelectedID => $Param{Trusted} || 0,
    );

    $Param{DispatchingOption} = $LayoutObject->BuildSelection(
        Data => {
            From  => Translatable('Dispatching by email To: field.'),
            Queue => Translatable('Dispatching by selected Queue.'),
        },
        Name       => 'DispatchingBy',
        SelectedID => $Param{DispatchingBy},
        Class      => 'Modernize Validate_Required ' . ( $Param{Errors}->{'DispatchingByInvalid'} || '' ),
    );

    $Param{QueueOption} = $LayoutObject->AgentQueueListOption(
        Data           => { $Kernel::OM->Get('Kernel::System::Queue')->QueueList( Valid => 1 ) },
        Name           => 'QueueID',
        SelectedID     => $Param{QueueID},
        OnChangeSubmit => 0,
        Class          => 'Modernize Validate_Required ' . ( $Param{Errors}->{'QueueIDInvalid'} || '' ),
    );
    $LayoutObject->Block(
        Name => 'Overview',
        Data => { %Param, },
    );
    $LayoutObject->Block(
        Name => 'ActionList',
    );
    $LayoutObject->Block(
        Name => 'ActionOverview',
    );
    $LayoutObject->Block(
        Name => 'OverviewAdd',
        Data => {
            %Param,
            %{ $Param{Errors} },
        },
    );

    return 1;
}

sub _AuthOAuthToken {
    my ( $Self, %Param ) = @_;
    my $LayoutObject = $Param{LayoutObject};
    my $ParamObject = $Param{ParamObject};
    my $OAuthObject = $Kernel::OM->Get('Kernel::System::OAuth');

    my %GetParam = ();
    my @Params   = (
        qw(ID)
    );
    for my $Parameter (@Params) {
        $GetParam{$Parameter} = $ParamObject->GetParam( Param => $Parameter );
    }

    my $OAuthConfig = $OAuthObject->EntryGet(
        ID => $GetParam{ID},
    );
    if (!defined($OAuthConfig)) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'Error',
            Message => "AdminMailAccount::_AuthOAuthToken : Invalid ID: $GetParam{ID}!",
        );
        return $LayoutObject->ErrorScreen(
            Message => "Invalid ID: $GetParam{ID}!",
        )
    }

    $OAuthObject->EntryUpdate(
        ID => $GetParam{ID},
        SessionID => $Self->{SessionID},
        UserID => $Self->{UserID},
    );

    my $URL = $OAuthObject->AuthURLGet(
        ID => $GetParam{ID},
        ClientID => $OAuthConfig->{ClientID},
        ClientSecret => $OAuthConfig->{ClientSecret},
    );

    return $LayoutObject->Redirect(
        ExtURL => $URL,
    );
}

sub _AccessCode {
    my ( $Self, %Param ) = @_;
    my $LayoutObject = $Param{LayoutObject};
    my $ParamObject = $Param{ParamObject};
    my $OAuthObject = $Kernel::OM->Get('Kernel::System::OAuth');
    my $LogObject = $Kernel::OM->Get('Kernel::System::Log');

    my $ID = $OAuthObject->GetIDFromSessionID(
        SessionID => $Self->{SessionID},
    );
    if (!defined($ID)) {
        $LogObject->Log(
            Priority => 'error',
            Message => "AdminMailAccount::_AccessCode Can't get mailAccount ID!",
        );
        return;
    }

    my $Code = $ParamObject->GetParam( Param => 'code' );

    $LogObject->Log(
        Priority => 'notice',
        Message => "AdminMailAccount::_AccessCode: ID=$ID, Code=$Code",
    );
    $OAuthObject->RequestToken(
        ID => $ID,
        Code => $Code,
    );
    return $LayoutObject->Redirect(
        OP => 'Action=AdminMailAccount',
    );
}

1;
