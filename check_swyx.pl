#! /usr/bin/perl -w
#
# check_swyx.pl - nagios plugin
# by Manuel Mahr manuel (at) it-mahr.com
# 
# Show Swyx Calls via SNMP incl. perfdata
# - total calls
# - active internal calls
# - active external calls
#
#
# Derived from check_ifoperstatus by Christoph Kron.
# by Manuel Mahr manuel (at) it-mahr.com
#
#
#
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.


use POSIX;
use Math::BigInt;
use strict;
use lib "/usr/local/nagios/libexec";
use utils qw($TIMEOUT %ERRORS &print_revision &support);

use Net::SNMP;
use Getopt::Long;
&Getopt::Long::config('bundling');

## function prototypes

sub print_help ();
sub usage ();
sub process_arguments ();
sub in_array ($@);

## module-specific variables

my $PROGNAME = "check_swyx.pl";
my $REVISION = '$Rev$';
my $debug;
my $exclude = '';
my $warnings = '';
my @all_exclude;
my @all_warnings;
my $countComponents = 0;
my $state = 'OK';
my $answer = "";

## variables for argument handling

my $status;

## snmp specific variables

my $timeout;
my $hostname;
my $session;
my $error;
my $response;
my $key;
my $lastc;
my $name;
my $community = "public";
my $snmp_version = 1;
my $maxmsgsize = 1472; # Net::SNMP default is 1472
my ($seclevel, $authproto, $secname, $authpass, $privpass, $auth, $priv);
my $context = "";
my $port = 161;
my @snmpoids;
my $oid_total_calls = '';
my $oid_active_exca = '';
my $oid_active_inca = '';
my $total_calls = '';
my $active_exca = '';
my $active_inca = '';
my $tmp;
my $opt_V;
my $opt_h;

## OIDs

$oid_total_calls = "1.3.6.1.4.1.23949.1.4.0";       # total calls
$oid_active_exca = "1.3.6.1.4.1.23949.1.2.0";		# active extern call
$oid_active_inca = "1.3.6.1.4.1.23949.1.3.0";		# active intern calls

## validate arguments

process_arguments();


## just in case of problems, let's avoid blocking the calling process for too long

$SIG{'ALRM'} = sub {
  print ("ERROR: No snmp response from $hostname (alarm)\n");
  exit $ERRORS{"UNKNOWN"};
};

alarm($timeout);

## main function

print "Swyx calls:";

## single value checks

push(@snmpoids, $oid_total_calls);
push(@snmpoids, $oid_active_exca);
push(@snmpoids, $oid_active_inca);

if ( ! defined($response = $session->get_request(@snmpoids)) ) {
  $answer=$session->error;
  $session->close;
  $state = 'WARNING';
  print "$state: SNMP error: $answer\n";
  exit $ERRORS{$state};
}


$total_calls = Math::BigInt->new($response->{$oid_total_calls});
$active_exca = Math::BigInt->new($response->{$oid_active_exca});
$active_inca = Math::BigInt->new($response->{$oid_active_inca});

# exit
if ( ! defined $debug && $state eq 'OK') {
  print " OK - total calls: $total_calls - active internal calls: $active_inca - active external calls: $active_exca | total_calls=$total_calls active_exca=$active_exca active_inca=$active_inca\n";
} else {
  print " OK - total calls: $total_calls - active internal calls: $active_inca - active external calls: $active_exca | total_calls=$total_calls active_exca=$active_exca active_inca=$active_inca\n";
}
exit $ERRORS{$state};


## subroutines

#
# $_[0] component OID
# $_[1] component name
# $_[2] component type
#
sub fetch_status {
  my $value;

  if ( ! defined ($response = $session->get_table($_[0]))) {
    print  " " . $_[1] . " - " . $_[0] . " (OID-tree not found, ignoring)\n" if (defined $debug);
    # tree not found, ignore!
    return -1;
  }

  while (($key, $value) = each %{$response}) {
    if ($value > 2) {
      # 1 = other/unknow  => assume OK
      # 2 = ok            => OK
      # 3 = failure/worse => CRITICAL/WARNING
      if (in_array($key, @all_warnings) && $state ne 'CRITICAL') {
        $state = 'WARNING';
      } else {
        $state = 'CRITICAL';
      }
    }
    if (defined $debug || $value > 2) {
      print " " . $_[1] . " (";
      if (defined $key && (length($key) > (length($_[0])+2))) {
        print substr($key, length($_[0])+1) . ":";
      }
      # eval to something like '$cpqGenericStates{$value}'
      $tmp = eval("\$" . $_[2] . "{" . $value . "}");
      if ($debug) {
        print $tmp."\n" if ($tmp ne "");
      } else {
        print $tmp." " if ($tmp ne "");
      }
      print ")";
    }
    $countComponents++;
    print "\n" if (defined $debug);
  }
}

sub in_array($@) {
   my $needle = shift(@_);
   my %items = map {$_ => 1} @_;
   return (exists($items{$needle})) ? 1 : 0;
}

sub usage() {
  printf "\nMissing arguments!\n";
  printf "\n";
  printf "Usage: \n";
  printf "check_netvision -H <HOSTNAME> [-C <community>] [-d] [-x excludecomponent1,excludecomponent2,...]\n";
  printf "Copyright (C) 2013 Guenther Mair\n";
  printf "\nUse 'check_netvision --help' for details.\n";
  printf "\n\n";
  exit $ERRORS{"UNKNOWN"};
}

sub print_help() {
  printf "check_netvision plugin for Nagios/Icinga\n";
  printf "\nModule specific parameters:\n";
  printf "   -d (--debug)      debug / verbose mode (print checked details)\n";
  printf "\nSNMP parameters:\n";
  printf "   -H (--hostname)   Hostname to query (required)\n";
  printf "   -C (--community)  SNMP read community (defaults to public,\n";
  printf "                     used with SNMP v1 and v2c\n";
  printf "   -v (--snmp_version)  1 for SNMP v1 (default)\n";
  printf "                        2 for SNMP v2c\n";
  printf "                        SNMP v2c will use get_bulk for less overhead\n";
  printf "   -L (--seclevel)   choice of \"noAuthNoPriv\", \"authNoPriv\", or \"authPriv\"\n";
  printf "   -U (--secname)    username for SNMPv3 context\n";
  printf "   -A (--authpass)   authentication password (cleartext ascii or localized key\n";
  printf "                     in hex with 0x prefix generated by using \"snmpkey\" utility\n";
  printf "                     auth password and authEngineID\n";
  printf "   -a (--authproto)  Authentication protocol (MD5 or SHA1)\n";
  printf "   -X (--privpass)   privacy password (cleartext ascii or localized key\n";
  printf "                     in hex with 0x prefix generated by using \"snmpkey\" utility\n";
  printf "                     privacy password and authEngineID\n";
  printf "   -p (--port)       SNMP port (default 161)\n";
  printf "   -M (--maxmsgsize) Max message size - usefull only for v1 or v2c\n";
  printf "   -t (--timeout)    seconds before the plugin times out (default=$TIMEOUT)\n";
  printf "   -V (--version)    Plugin version\n";
  printf "   -h (--help)       usage help \n\n";
  print_revision($PROGNAME, '$Revision: 48 $');
}

sub process_arguments() {
  $status = GetOptions(
    "V"   => \$opt_V,        "version"        => \$opt_V,
    "h"   => \$opt_h,        "help"           => \$opt_h,
    "d"   => \$debug,        "debug"          => \$debug,
    "v=i" => \$snmp_version, "snmp_version=i" => \$snmp_version,
    "C=s" => \$community,    "community=s"    => \$community,
    "L=s" => \$seclevel,     "seclevel=s"     => \$seclevel,
    "a=s" => \$authproto,    "authproto=s"    => \$authproto,
    "U=s" => \$secname,      "secname=s"      => \$secname,
    "A=s" => \$authpass,     "authpass=s"     => \$authpass,
    "X=s" => \$privpass,     "privpass=s"     => \$privpass,
    "p=i" => \$port,         "port=i"         => \$port,
    "H=s" => \$hostname,     "hostname=s"     => \$hostname,
    "M=i" => \$maxmsgsize,   "maxmsgsize=i"   => \$maxmsgsize,
    "t=i" => \$timeout,      "timeout=i"      => \$timeout,
  );

  @all_exclude = split(/,/, $exclude);
  @all_warnings = split(/,/, $warnings);

  if ($status == 0) {
    print_help();
    exit $ERRORS{'OK'};
  }

  if ($opt_V) {
    print_revision($PROGNAME,'$Revision: 48 $');
    exit $ERRORS{'OK'};
  }

  if ($opt_h) {
    print_help();
    exit $ERRORS{'OK'};
  }

  if (!utils::is_hostname($hostname)) {
    usage();
    exit $ERRORS{"UNKNOWN"};
  }

  $timeout = $TIMEOUT unless (defined $timeout);

  if ($snmp_version =~ /3/) {
    # Must define a security level even though default is noAuthNoPriv
    # v3 requires a security username
    if (defined $seclevel  && defined $secname) {

      # Must define a security level even though defualt is noAuthNoPriv
      unless ( grep /^$seclevel$/, qw(noAuthNoPriv authNoPriv authPriv) ) {
        usage();
        exit $ERRORS{"UNKNOWN"};
      }

      # Authentication wanted
      if ( $seclevel eq 'authNoPriv' || $seclevel eq 'authPriv' ) {
        unless ( $authproto eq 'MD5' || $authproto eq 'SHA1' ) {
          usage();
          exit $ERRORS{"UNKNOWN"};
        }

        if ( ! defined $authpass) {
          usage();
          exit $ERRORS{"UNKNOWN"};
        } else {
          if ($authpass =~ /^0x/) {
            $auth = "-authkey => $authpass" ;
          } else {
            $auth = "-authpassword => $authpass";
          }
        }
      }

      # Privacy (DES encryption) wanted
      if ($seclevel eq 'authPriv') {
        if ( ! defined $privpass) {
          usage();
          exit $ERRORS{"UNKNOWN"};
        } else {
          if ($privpass =~ /^0x/) {
            $priv = "-privkey => $privpass";
          } else {
            $priv = "-privpassword => $privpass";
          }
        }
      }
    } else {
      usage();
      exit $ERRORS{'UNKNOWN'}; ;
    }
  } # end snmpv3

  # start snmpv1 / snmpv2
  if ($snmp_version =~ /[12]/) {
    ($session, $error) = Net::SNMP->session(
      -hostname   => $hostname,
      -community  => $community,
      -port       => $port,
      -version    => $snmp_version,
      -maxmsgsize => $maxmsgsize
    );

    if ( ! defined($session)) {
      $state='UNKNOWN';
      $answer=$error;
      print ("$state: $answer");
      exit $ERRORS{$state};
    }

  } elsif ($snmp_version =~ /3/) {

    if ($seclevel eq 'noAuthNoPriv') {
      ($session, $error) = Net::SNMP->session(
        -hostname => $hostname,
        -port     => $port,
        -version  => $snmp_version,
        -username => $secname
      );
    } elsif ($seclevel eq 'authNoPriv') {
      ($session, $error) = Net::SNMP->session(
        -hostname     => $hostname,
        -port         => $port,
        -version      => $snmp_version,
        -username     => $secname,
        $auth,
        -authprotocol => $authproto
      );
    } elsif ($seclevel eq 'authPriv') {
      ($session, $error) = Net::SNMP->session(
        -hostname     => $hostname,
        -port         => $port,
        -version      => $snmp_version,
        -username     => $secname,
        $auth,
        -authprotocol => $authproto,
        $priv
      );
    }

    if ( ! defined($session)) {
      $state='UNKNOWN';
      $answer=$error;
      print ("$state: $answer");
      exit $ERRORS{$state};
    }

  } else {
    $state='UNKNOWN';
    print ("$state: No support for SNMP v$snmp_version yet\n");
    exit $ERRORS{$state};
  }
}
## End validation
