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

# Purpose of smbldap-groupadd : group (posix) add

use strict;
use smbldap_tools;

use Getopt::Std;
my %Options;

my $ok = getopts('og:?', \%Options);
if ( (!$ok) || (@ARGV < 1) || ($Options{'?'}) ) {
	print "Usage: $0 [-go?] groupname\n";
	print "  -g	gid\n";
	print "  -o	gid is not unique\n";
	print "  -?	show this help message\n";
	exit (1);
}

my $_groupName = $ARGV[0];

if (defined(get_group_dn($_groupName))) {
    print "$0: group $_groupName exists\n";
    exit (6);
}

my $_groupGidNumber = $Options{'g'};

if (!group_add($_groupName, $_groupGidNumber, $Options{'o'})) {
    print "$0: error adding group $_groupName\n";
    exit (6);
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

