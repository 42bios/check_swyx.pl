#!/usr/bin/env perl
# check_swyx.v2.pl - simplified Swyx SNMP check for Nagios/Icinga
# License: GPL-2.0-or-later

use strict;
use warnings;
use Getopt::Long qw(:config no_ignore_case bundling);
use Net::SNMP;

my $host = '';
my $version = 2;
my $community = 'public';
my $username = '';
my $auth_password = '';
my $auth_protocol = 'sha';
my $priv_password = '';
my $priv_protocol = 'aes';
my $help = 0;

GetOptions(
    'host|H=s'         => \$host,
    'version|v=i'      => \$version,
    'community|C=s'    => \$community,
    'username|U=s'     => \$username,
    'authpassword|A=s' => \$auth_password,
    'authprotocol|a=s' => \$auth_protocol,
    'privpassword|X=s' => \$priv_password,
    'privprotocol|x=s' => \$priv_protocol,
    'help|h|?'         => \$help,
) or usage(3, 'UNKNOWN - Invalid arguments');

usage(0) if $help;
usage(3, 'UNKNOWN - Missing required -H/--host') if !$host;

my %oids = (
    total_calls => '1.3.6.1.4.1.23949.1.4.0',
    active_exca => '1.3.6.1.4.1.23949.1.2.0',
    active_inca => '1.3.6.1.4.1.23949.1.3.0',
);

my ($session, $error) = create_snmp_session();
if (!$session) {
    print "CRITICAL - SNMP session error: $error\n";
    exit 2;
}

my $result = $session->get_request(-varbindlist => [ values %oids ]);
if (!defined $result) {
    my $err = $session->error();
    $session->close();
    print "CRITICAL - SNMP query failed: $err\n";
    exit 2;
}

$session->close();

my $total = to_num($result->{$oids{total_calls}});
my $exca  = to_num($result->{$oids{active_exca}});
my $inca  = to_num($result->{$oids{active_inca}});

if (!defined($total) || !defined($exca) || !defined($inca)) {
    print "UNKNOWN - Received invalid SNMP data\n";
    exit 3;
}

print "OK - total calls: $total - active internal calls: $inca - active external calls: $exca";
print " | total_calls=$total active_exca=$exca active_inca=$inca\n";
exit 0;

sub create_snmp_session {
    if ($version == 3) {
        return Net::SNMP->session(
            -hostname     => $host,
            -port         => 161,
            -version      => 3,
            -username     => $username,
            -authpassword => $auth_password,
            -authprotocol => lc($auth_protocol),
            -privpassword => $priv_password,
            -privprotocol => lc($priv_protocol),
            -timeout      => 5,
            -retries      => 2,
        );
    }

    return Net::SNMP->session(
        -hostname  => $host,
        -community => $community,
        -port      => 161,
        -version   => $version,
        -timeout   => 5,
        -retries   => 2,
    );
}

sub to_num {
    my ($v) = @_;
    return undef if !defined $v;
    if ($v =~ /(-?\d+(?:\.\d+)?)/) {
        return 0 + $1;
    }
    return undef;
}

sub usage {
    my ($exit_code, $msg) = @_;
    print "$msg\n" if defined $msg;
    print <<'USAGE';
check_swyx.v2.pl

Usage:
  check_swyx.v2.pl -H <host> [-C <community>] [-v <1|2|3>] [options]

SNMP v1/v2c:
  -H, --host           Hostname or IP
  -C, --community      Community (default: public)
  -v, --version        1 or 2 (default: 2)

SNMP v3:
  -v, --version        3
  -U, --username       Username
  -A, --authpassword   Auth password
  -a, --authprotocol   sha|md5 (default: sha)
  -X, --privpassword   Privacy password
  -x, --privprotocol   aes|des (default: aes)

  -h, --help           Show this help
USAGE
    exit $exit_code;
}
