#!/usr/bin/env perl

use strict;
use warnings;

use CGI;
use URI::Escape;

my $cgi = CGI->new();
my $Code = uri_escape($cgi->param('code'));

my $url = $ENV{SCRIPT_NAME};
$url =~ s/accesstoken.pl/index.pl/;

print "Status: 302 Moved Temporarily\n";
print "Location: $url?Action=AdminMailAccount;Subaction=AccessCode&code=$Code\n";
print "\n";

1;
