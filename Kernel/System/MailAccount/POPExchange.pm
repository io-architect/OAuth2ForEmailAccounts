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

package Kernel::System::MailAccount::POPExchange;

use strict;
use warnings;

use Net::POP3;
use Net::Cmd;

use parent qw(Kernel::System::MailAccount::POP3);

our @ObjectDependencies = (
    'Kernel::System::Log',
);

# Use Net::SSLGlue::POP3 on systems with older Net::POP3 modules that cannot handle POP3S.
BEGIN {
    if ( !defined &Net::POP3::starttls ) {
        ## nofilter(TidyAll::Plugin::OTOBO::Perl::Require)
        ## nofilter(TidyAll::Plugin::OTOBO::Perl::SyntaxCheck)
        require Net::SSLGlue::POP3;
    }
}

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

    my $Type = 'POP3S';

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

    # connect to host
    my $PopObject = Net::POP3->new(
        'outlook.office365.com:995',
        Timeout         => $Param{Timeout},
        Debug           => $Param{Debug},
        SSL             => 1,
        SSL_verify_mode => 0,
    );

    if ( !$PopObject ) {
        return (
            Successful => 0,
            Message    => "$Type: Can't connect to $Param{Host}"
        );
    }

    my $Resp = $PopObject->command('AUTH', 'XOAUTH2');
    if (!defined($Resp)) {
        return (
            Successful => 0,
            Message => "Auth request failed!",
        );
    }
    my $ServerResp = $Resp->response();

    $Resp = $PopObject->command($AuthString);
    $ServerResp = $Resp->response();
    if ($ServerResp != CMD_OK) {
        return (
            Successful => 0,
            Message => "Auth server response failed!",
        );
    }


    my $Messages = $PopObject->list();
    if (!defined($Messages)) {
        return (
            Successful => 0,
            Message => "LIST failed!",
        );
    }
    my $NOM = scalar(keys(%$Messages));
    if (!$NOM) {
        $NOM = '0E0';
    }

    return (
        Successful => 1,
        PopObject  => $PopObject,
        NOM        => $NOM,
        Type       => $Type,
    );
}

1;
