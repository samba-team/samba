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

# Purpose of smbldap-groupmod : group (posix) modification


use strict;
use smbldap_tools;
use smbldap_conf;


#####################

use Getopt::Std;
my %Options;

my $ok = getopts('og:n:m:x:?', \%Options);
if ( (!$ok) || (@ARGV < 1) || ($Options{'?'}) ) {
	print "Usage: $0 [-g gid [-o]] [-n name] [-m members(,)] [-x members (,)] groupname\n";
	print "  -g	new gid\n";
	print "  -o	gid is not unique\n";
	print "  -n	new group name\n";
	print "  -m	add members (comma delimited)\n";
	print "  -x	delete members (comma delimted)\n";
	print "  -?	show this help message\n";
	exit (1);
}

my $groupName = $ARGV[0];

if (!defined(get_group_dn($groupName))) {
    print "$0: group $groupName doesn't exist\n";
    exit (6);
}

my $newname = $Options{'n'};

my $nscd_status = system "/etc/init.d/nscd status >/dev/null 2>&1";

if ($nscd_status == 0) {
   system "/etc/init.d/nscd restart > /dev/null 2>&1";
}

my $gid = getgrnam($groupName);

my $tmp;
if (defined($tmp = $Options{'g'}) and $tmp =~ /\d+/) {
    if (!defined($Options{'o'})) {
	if (defined(getgrgid($tmp))) {
	    print "$0: gid $tmp exists\n";
	    exit (6);
	}
    }
    if (!($gid == $tmp)) {
	my $tmpldif =
"dn: cn=$groupName,$groupsdn
changetype: modify
replace: gidNumber
gidNumber: $tmp

";
	die "$0: error while modifying group $groupName\n"
	    unless (do_ldapmodify($tmpldif) == 0);
	undef $tmpldif;

    }
}

if (defined($newname)) {
    my $FILE="|$ldapmodrdn >/dev/null";
    open (FILE, $FILE) || die "$!\n";
    print FILE <<EOF;
cn=$groupName,$groupsdn
cn=$newname

EOF
    ;
    close FILE;
    die "$0: error while modifying group $groupName\n" if ($?);

    my $tmpldif =
"dn: cn=$newname,$groupsdn
changetype: modify
delete: cn
-
add: cn
cn: $newname

";
    die "$0: error while modifying group $groupName\n"
	unless (do_ldapmodify($tmpldif) == 0);
    undef $tmpldif;

}

# Add members
if (defined($Options{'m'})) {
	my $members = $Options{'m'};
	my @members = split( /,/, $members );
	my $member;
	foreach $member ( @members ) {
		my $tmpldif =
"dn: cn=$groupName,$groupsdn
changetype: modify
add: memberUid
memberUid: $member

";
		die "$0: error while modifying group $groupName\n"
			unless (do_ldapmodify($tmpldif) == 0);
		undef $tmpldif;
	}
}

# Delete members
if (defined($Options{'x'})) {
        my $members = $Options{'x'};
        my @members = split( /,/, $members );
        my $member;
        foreach $member ( @members ) {
                my $tmpldif =
"dn: cn=$groupName,$groupsdn
changetype: modify
delete: memberUid
memberUid: $member

";
                die "$0: error while modifying group $groupName\n"
                        unless (do_ldapmodify($tmpldif) == 0);
                undef $tmpldif;
        }
}

$nscd_status = system "/etc/init.d/nscd status >/dev/null 2>&1";

if ($nscd_status == 0) {
   system "/etc/init.d/nscd restart > /dev/null 2>&1";
}

exit (0);

############################################################

=head1 NAME

       smbldap-groupmod.pl - Modify a group

=head1 SYNOPSIS

       smbldap-groupmod.pl [-g gid [-o]] [-n group_name ] group

=head1 DESCRIPTION

       The smbldap-groupmod.pl command modifies the system account files to
       reflect the changes that are specified on the command line.
       The options which apply to the smbldap-groupmod command are

       -g gid The numerical value of the group's ID. This value must be
              unique, unless the -o option is used. The value must be non-
              negative. Any files which the old group ID is the file
              group ID must have the file group ID changed manually.

       -n group_name
              The name of the group will be changed from group to group_name.

       -m members
	      The members to be added to the group in comma-delimeted form.

       -x members
	      The members to be removed from the group in comma-delimted form.

=head1 EXAMPLES

       smbldap-groupmod.pl -g 253 development
	      This will change the GID of the 'development' group to '253'.

       smbldap-groupmod.pl -n Idiots Managers
	      This will change the name of the 'Managers' group to 'Idiots'.

       smbldap-groupmod.pl -m "jdoe,jsmith" "Domain Admins"
	      This will add 'jdoe' and 'jsmith' to the 'Domain Admins' group.

       smbldap-groupmod.pl -x "jdoe,jsmith" "Domain Admins"
	      This will remove 'jdoe' and 'jsmith' from the 'Domain Admins' group.

=head1 SEE ALSO

       groupmod(1)

=cut

#'
