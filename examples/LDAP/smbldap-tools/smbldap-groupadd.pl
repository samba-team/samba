#!/usr/bin/perl -w

#  This code was developped by IDEALX (http://IDEALX.org/) and
#  contributors (their names can be found in the CONTRIBUTORS file).
#
#                 Copyright (C) 2001-2002 IDEALX
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation; either version 2
#  of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307,
#  USA.

# Purpose of smbldap-groupadd : group (posix) add

use strict;
use FindBin;
use FindBin qw($RealBin);
use lib "$RealBin/";
use smbldap_tools;
use smbldap_conf;
use Getopt::Std;
my %Options;

my $ok = getopts('ag:or:s:t:p?', \%Options);
if ( (!$ok) || (@ARGV < 1) || ($Options{'?'}) ) {
  print "Usage: $0 [-agorst?] groupname\n";
  print "  -a   add automatic group mapping entry\n";
  print "  -g   gid\n";
  print "  -o   gid is not unique\n";
  print "  -r   group-rid\n";
  print "  -s   group-sid\n";
  print "  -t   group-type\n";
  print "  -p   print the gidNumber to stdout\n";
  print "  -?   show this help message\n";
  exit (1);
}

my $_groupName = $ARGV[0];

if (defined(get_group_dn($_groupName))) {
  warn "$0: group $_groupName exists\n";
  exit (6);
}

my $_groupGidNumber = $Options{'g'};
if (! defined ($_groupGidNumber = group_add($_groupName, $_groupGidNumber, $Options{'o'}))) {
  warn "$0: error adding group $_groupName\n";
  exit (6);
}

my $group_sid;
my $tmp;
if ($tmp= $Options{'s'}) {
  if ($tmp =~ /^S-(?:\d+-)+\d+$/) {
    $group_sid = $tmp;
  } else {
    warn "$0: illegal group-rid $tmp\n";
    exit(7);
  }
} elsif ($Options{'r'} || $Options{'a'}) {
  my $group_rid;
  if ($tmp= $Options{'r'}) {
    if ($tmp =~ /^\d+$/) {
      $group_rid = $tmp;
    } else {
      warn "$0: illegal group-rid $tmp\n";
      exit(7);
    }
  } else {
    # algorithmic mapping
    $group_rid = 2*$_groupGidNumber+1001;
  }
  $group_sid = $SID.'-'.$group_rid;
}

if ($Options{'r'} || $Options{'a'} || $Options{'s'}) {
  # let's test if this SID already exist
  my $test_exist_sid=does_sid_exist($group_sid,$groupsdn);
  if ($test_exist_sid->count == 1) {
	warn "Group SID already owned by\n";
	# there should not exist more than one entry, but ...
	foreach my $entry ($test_exist_sid->all_entries) {
	  my $dn= $entry->dn;
	  chomp($dn);
	  warn "$dn\n";
	}
	exit(7);
  }
}

if ($group_sid) {
  my $group_type;
  my $tmp;
  if ($tmp= $Options{'t'}) {
    unless (defined($group_type = &group_type_by_name($tmp))) {
      warn "$0: unknown group type $tmp\n";
      exit(8);
    }
  } else {
    $group_type = group_type_by_name('domain');
  }
  my $ldap_master=connect_ldap_master();
  my $modify = $ldap_master->modify ( "cn=$_groupName,$groupsdn",
									  add => {
											  'objectClass' => 'sambaGroupMapping',
											  'sambaSID' => $group_sid,
											  'sambaGroupType' => $group_type
											 }
									);
  $modify->code && warn "failed to delete entry: ", $modify->error ;
  # take down session
  $ldap_master->unbind
}

if ($Options{'p'}) {
  print STDOUT "$_groupGidNumber";
}
exit(0);

########################################

=head1 NAME

       smbldap-groupadd.pl - Create a new group

=head1 SYNOPSIS

       smbldap-groupadd.pl [-g gid [-o]] group

=head1 DESCRIPTION
       The smbldap-groupadd.pl command creates a new group account using
       the values specified on the command line and the default values
       from the system. The new group will be entered into the system
       files as needed. The options which apply to the groupadd command are

       -g gid The numerical value of the group's ID. This value must be
              unique, unless the -o option is used. The value must be non-
              negative. The default is to use the smallest ID value greater
              than 1000 and greater than every other group.

=head1 SEE ALSO

       groupadd(1)

=cut

#'

