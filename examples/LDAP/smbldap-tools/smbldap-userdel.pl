#!/usr/bin/perl

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

# Purpose of smbldap-userdel : user (posix,shadow,samba) deletion

use strict;
use FindBin;
use FindBin qw($RealBin);
use lib "$RealBin/";
use smbldap_tools;


#####################

use Getopt::Std;
my %Options;

my $ok = getopts('r?', \%Options);

if ( (!$ok) || (@ARGV < 1) || ($Options{'?'}) ) {
  print "Usage: $0 [-r?] username\n";
  print "  -r	remove home directory\n";
  exit (1);
}

# Read only first @ARGV
my $user = $ARGV[0];

my $dn;
# user must not exist in LDAP
if (!defined($dn=get_user_dn($user))) {
  print "$0: user $user does not exist\n";
  exit (6);
}

if ($< != 0) {
  print "You must be root to delete an user\n";
  exit (1);
}

my $homedir;
if (defined($Options{'r'})) {
  $homedir=get_homedir($user);
}

# remove user from groups
my $groups = find_groups_of $user;
my @grplines = split(/\n/,$groups);

my $grp;
foreach $grp (@grplines) {
  my $gname = "";
  if ( $grp =~ /dn: cn=([^,]+),/) {
	$gname = $1;
	#print "xx $gname\n";
  }
  if ($gname ne "") {
	group_remove_member($gname, $user);
  }
}

# XXX
delete_user($user);

# delete dir -- be sure that homeDir is not a strange value
if (defined($Options{'r'})) {
  if ($homedir !~ /^\/dev/ and $homedir !~ /^\/$/) {
	system "rm -rf $homedir";
  }
}

my $nscd_status = system "/etc/init.d/nscd status >/dev/null 2>&1";

if ($nscd_status == 0) {
   system "/etc/init.d/nscd restart > /dev/null 2>&1";
}

exit (0);

############################################################

=head1 NAME

       smbldap-userdel.pl - Delete a user account and related files

=head1 SYNOPSIS

       smbldap-userdel.pl [-r] login

=head1 DESCRIPTION

       The smbldap-userdel.pl command modifies the system
       account files, deleting all entries that refer to login.
       The named user must exist.

       -r     Files in the user's home directory will be removed along with
              the home directory itself. Files located in other file
              systems will have to be searched for and deleted manually.

=head1 SEE ALSO

       userdel(1)

=cut

#'
