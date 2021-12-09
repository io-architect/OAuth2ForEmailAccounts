package Kernel::System::MailAccount::IMAPGmail;

use strict;
use warnings;

# There are currently errors on Perl 5.20 on Travis, disable this check for now.
## nofilter(TidyAll::Plugin::OTOBO::Perl::SyntaxCheck)
use IO::Socket::SSL;

use Data::Dumper;

use parent qw(Kernel::System::MailAccount::IMAP);

our @ObjectDependencies = (
    'Kernel::System::Log',
);

sub Connect {
    my ( $Self, %Param ) = @_;

    # check needed stuff
    for (qw(Login Password Host Timeout Debug)) {
        if ( !defined $Param{$_} ) {
            return (
                Successful => 0,
                Message    => "Need $_!",
            );
        }
    }

    my $OAuthObject = $Kernel::OM->Get('Kernel::System::OAuth');

    my $ID = $OAuthObject->GetIDFromMailAddress(
        MailAddress => $Param{Login},
        Host => $Param{Host},
    );
    if (!defined($ID)) {
        return (
            Successful => 0,
            Message => "Invalid login $Param{Login}",
        );
    }

    my $AuthString = $OAuthObject->AuthStringGet(
        ID => $ID,
        MailAccount => $Param{Login},
    );
    if (!defined($AuthString)) {
        return (
            Successful => 0,
            Message => "Can't get auth string",
        )
    }

    my $Type = 'IMAPS';

    # connect to host
    my $IMAPObject = Net::IMAP::Simple->new(
        'imap.gmail.com:993',
        timeout     => $Param{Timeout},
        debug       => $Param{Debug},
        use_ssl     => 1,
        ssl_options => [
            SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE(),
        ],
    );
    if ( !$IMAPObject ) {
        return (
            Successful => 0,
            Message    => "$Type: Can't connect to imap.gmail.com:993"
        );
    }

    # authentication
    my $Auth = $IMAPObject->_process_cmd(
        cmd => [ AUTHENTICATE => qq[ XOAUTH2 $AuthString] ],
        final => sub { 1; },
        process => sub {},
    );

    if (!defined($Auth)) {
        return (
            Successful => 0,
            Message => "Auth failed.",
        )
    }

    return (
        Successful => 1,
        IMAPObject => $IMAPObject,
        Type       => $Type,
    );
}

1;
