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

# Purpose of smbldap-groupdel : group (posix) deletion

use strict;
use FindBin;
use FindBin qw($RealBin);
use lib "$RealBin/";
use smbldap_tools;
use smbldap_conf;

#####################
use Getopt::Std;
my %Options;

my $ok = getopts('?', \%Options);
if ( (!$ok) || (@ARGV < 1) || ($Options{'?'}) ) {
  print "Usage: $0 groupname\n";
  print "  -?	show this help message\n";
  exit (1);
}

my $_groupName = $ARGV[0];

my $dn_line;
if (!defined($dn_line = get_group_dn($_groupName))) {
  print "$0: group $_groupName doesn't exist\n";
  exit (6);
}

my $dn = get_dn_from_line($dn_line);

group_del($dn);

my $nscd_status = system "/etc/init.d/nscd status >/dev/null 2>&1";

if ($nscd_status == 0) {
  system "/etc/init.d/nscd restart > /dev/null 2>&1";
}

#if (defined($dn_line = get_group_dn($_groupName))) {
#    print "$0: failed to delete group\n";
#    exit (7);
#}


exit (0);

############################################################

=head1 NAME

       smbldap-groupdel.pl - Delete a group

=head1 SYNOPSIS

       smbldap-groupdel.pl group

=head1 DESCRIPTION

       The smbldap-groupdel.pl command modifies the system account files,
       deleting all entries that refer to group. The named group must exist.

       You must manually check all filesystems to insure that no files remain
       with the named group as the file group ID.

=head1 SEE ALSO

       groupdel(1)

=cut

#'
