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

# Purpose of smbldap-usermod : user (posix,shadow,samba) modification

use strict;
use smbldap_tools;
use smbldap_conf;


#####################

use Getopt::Std;
my %Options;
my $nscd_status;

my $ok = getopts('A:B:C:D:E:F:H:IJxme:f:u:g:G:d:l:s:c:ok:?', \%Options);
if ( (!$ok) || (@ARGV < 1) || ($Options{'?'}) ) {
	print "Usage: $0 [-awmugdsckxABCDEFGHI?] username\n";
	print "  -c	gecos\n";
	print "  -d	home directory\n";
	#print "  -m	move home directory\n";
	#print "  -e	expire date (YYYY-MM-DD)\n";
	#print "  -f	inactive days\n";
	print "  -u	uid\n";
	print "  -o	uid can be non unique\n";
	print "  -g	gid\n";
	print "  -G	supplementary groups (comma separated)\n";
	print "  -l	login name\n";
	print "  -s	shell\n";
	print "  -x	creates rid and primaryGroupID in hex instead of decimal (for Samba 2.2.2 unpatched only)\n";
	print "  -A	can change password ? 0 if no, 1 if yes\n";
	print "  -B	must change password ? 0 if no, 1 if yes\n";
	print "  -C	sambaHomePath (SMB home share, like '\\\\PDC-SRV\\homes')\n";
	print "  -D	sambaHomeDrive (letter associated with home share, like 'H:')\n";
	print "  -E	sambaLogonScript (DOS script to execute on login)\n";
	print "  -F	sambaProfilePath (profile directory, like '\\\\PDC-SRV\\profiles\\foo')\n";
	print "  -H	sambaAcctFlags (samba account control bits like '[NDHTUMWSLKI]')\n";
	print "  -I	disable an user. Can't be used with -H or -J\n";
	print "  -J	enable an user. Can't be used with -H or -I\n";
	print "  -?	show this help message\n";
	exit (1);
}

if ($< != 0) {
    print "You must be root to modify an user\n";
    exit (1);
}

# Read only first @ARGV
my $user = $ARGV[0];

# Read user datas
my $lines = read_user($user);
if (!defined($lines)) {
    print "$0: user $user doesn't exist\n";
    exit (1);
}

#print "$lines\n";
my $dn_line;
if ( $lines =~ /(^dn: .*)/ ) {
    $dn_line = $1;
}

chomp($dn_line);

my $samba = 0;
if ($lines =~ m/objectClass: sambaAccount/) {
    $samba = 1;
}

############

my $tmp;
my $mods;

# Process options
my $changed_uid;
my $_userUidNumber;
my $_userRid;
if (defined($tmp = $Options{'u'})) {
    if (defined($Options{'o'})) {
	$nscd_status = system "/etc/init.d/nscd status >/dev/null 2>&1";
	
	if ($nscd_status == 0) {
	    system "/etc/init.d/nscd stop > /dev/null 2>&1";
	}

	if (getpwuid($tmp)) {
	    if ($nscd_status == 0) {
		system "/etc/init.d/nscd start > /dev/null 2>&1";
	    }

	    print "$0: uid number $tmp exists\n";
	    exit (6);
	}
	if ($nscd_status == 0) {
	    system "/etc/init.d/nscd start > /dev/null 2>&1";
	}

    }
    $_userUidNumber = $tmp;
    # as rid we use 2 * uid + 1000
    my $_userRid = 2 * $_userUidNumber + 1000;
    if (defined($Options{'x'})) {
	$_userRid= sprint("%x", $_userRid);
    }
    $mods .= "uidNumber: $_userUidNumber\n";
    if ($samba) {
	$mods .= "rid: $_userRid\n";
    }
    $changed_uid = 1;
}

my $changed_gid;
my $_userGidNumber;
my $_userGroupRid;
if (defined($tmp = $Options{'g'})) {
    $_userGidNumber = parse_group($tmp);
    if ($_userGidNumber < 0) {
	print "$0: group $tmp doesn't exist\n";
	exit (6);
    }
# as grouprid we use 2 * gid + 1001
    my $_userGroupRid = 2 * $_userGidNumber + 1001;
    if (defined($Options{'x'})) {
	$_userGroupRid = sprint("%x", $_userGroupRid);
    }
    $mods .= "gidNumber: $_userGidNumber\n";
    if ($samba) {
	$mods .= "primaryGroupID: $_userGroupRid\n";
    }
    $changed_gid = 1;
}

my $changed_shell;
my $_userLoginShell;
if (defined($tmp = $Options{'s'})) {
    $_userLoginShell = $tmp;
    $mods .= "loginShell: $_userLoginShell\n";
    $changed_shell = 1;
}

my $changed_gecos;
my $_userGecos;
if (defined($tmp = $Options{'c'})) { 
    $_userGecos = $tmp;
    $mods .= "gecos: $_userGecos\n";
    $changed_gecos = 1;
}

my $changed_homedir;
my $newhomedir;
if (defined($tmp = $Options{'d'})) {
    $newhomedir = $tmp; 
    $mods .= "homeDirectory: $newhomedir\n";
    $changed_homedir = 1;
}


if (defined($tmp = $Options{'G'})) {

    # remove user from old groups
    my $groups = find_groups_of $user;
    my @grplines = split(/\n/, $groups);

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

    # add user to new groups
    add_grouplist_user($tmp, $user);
}

#
# A : sambaPwdCanChange
# B : sambaPwdMustChange
# C : sambaHomePath
# D : sambaHomeDrive
# E : sambaLogonScript
# F : sambaProfilePath
# H : sambaAcctFlags

my $attr;
my $winmagic = 2147483647;

if (defined($tmp = $Options{'A'})) {
    $attr = "sambaPwdCanChange";
    if ($tmp != 0) {
	$mods .= "$attr: 0\n";
    } else {
	$mods .= "$attr: $winmagic\n";
    }
}

if (defined($tmp = $Options{'B'})) {
    $attr = "sambaPwdMustChange";
    if ($tmp != 0) {
	$mods .= "$attr: 0\n";
    } else {
	$mods .= "$attr: $winmagic\n";
    }
}

if (defined($tmp = $Options{'C'})) {
    $attr = "sambaHomePath";
    #$tmp =~ s/\\/\\\\/g;
    $mods .= "$attr: $tmp\n";
}

if (defined($tmp = $Options{'D'})) {
    $attr = "sambaHomeDrive";
    $tmp = $tmp.":" unless ($tmp =~ /:/);
    $mods .= "$attr: $tmp\n";
}

if (defined($tmp = $Options{'E'})) {
    $attr = "sambaLogonScript";
    #$tmp =~ s/\\/\\\\/g;
    $mods .= "$attr: $tmp\n";
}

if (defined($tmp = $Options{'F'})) {
    $attr = "sambaProfilePath";
    #$tmp =~ s/\\/\\\\/g;
    $mods .= "$attr: $tmp\n";
}

if (defined($tmp = $Options{'H'})) {
    $attr = "sambaAcctFlags";
    #$tmp =~ s/\\/\\\\/g;
    $mods .= "$attr: $tmp\n";
} elsif (defined($tmp = $Options{'I'})) {
    my $flags;

    if ( $lines =~ /^sambaAcctFlags: (.*)/m ) {
	$flags = $1;
    }

    chomp($flags);

    if ( !($flags =~ /D/) ) {
	my $letters;
	if ($flags =~ /(\w+)/) {
	    $letters = $1;
	}
	$mods .= "sambaAcctFlags: \[D$letters\]\n";
    }
} elsif (defined($tmp = $Options{'J'})) {
    my $flags;

    if ( $lines =~ /^sambaAcctFlags: (.*)/m ) {
	$flags = $1;
    }

    chomp($flags);

    if ( $flags =~ /D/ ) {
	my $letters;
	if ($flags =~ /(\w+)/) {
	    $letters = $1;
	}
	$letters =~ s/D//;
	$mods .= "sambaAcctFlags: \[$letters\]\n";
    }
}

if ($mods ne '') {
    #print "----\n$dn_line\n$mods\n----\n";

    my $tmpldif =
"$dn_line
changetype: modify
$mods
";

    die "$0: error while modifying user $user\n"
	unless (do_ldapmodify($tmpldif) == 0);

    undef $tmpldif;
}

$nscd_status = system "/etc/init.d/nscd status >/dev/null 2>&1";

if ($nscd_status == 0) {
   system "/etc/init.d/nscd restart > /dev/null 2>&1";
}


############################################################

=head1 NAME

       smbldap-usermod.pl - Modify a user account

=head1 SYNOPSIS

       smbldap-usermod.pl [-c comment] [-d home_dir]
               [-g initial_group] [-G group[,...]]
               [-l login_name] [-p passwd]
               [-s shell] [-u uid [ -o]] [-x]
               [-A canchange] [-B mustchange] [-C smbhome]
               [-D homedrive] [-E scriptpath] [-F profilepath]
               [-H acctflags] login

=head1 DESCRIPTION

       The  smbldap-usermod.pl  command  modifies the system account files
       to reflect the changes that are specified on the  command  line.
       The  options  which apply to the usermod command are

       -c comment
              The new value of the user's comment field (gecos).

       -d home_dir
              The user's new login directory.

       -g initial_group
              The group name or number of the user's new initial login  group.
              The  group  name  must  exist.   A group number must refer to an
              already existing group.  The default group number is 1.

       -G group,[...]
              A list of supplementary groups which the user is also  a  member
              of.   Each  group is separated from the next by a comma, with no
              intervening whitespace.  The groups  are  subject  to  the  same
              restrictions as the group given with the -g option.  If the user
              is currently a member of a group which is not listed,  the  user
              will be removed from the group

       -l login_name
              The  name  of the user will be changed from login to login_name.
              Nothing else is changed.  In particular, the user's home  direc­
              tory  name  should  probably be changed to reflect the new login
              name.

       -s shell
              The name of the user's new login shell.  Setting this  field  to
              blank causes the system to select the default login shell.

       -u uid The  numerical  value  of  the  user's  ID.   This value must be
              unique, unless the -o option is used.  The value  must  be  non-
              negative.  Any files which the user owns  and  which  are
              located  in  the directory tree rooted at the user's home direc­
              tory will have the file user ID  changed  automatically.   Files
              outside of the user's home directory must be altered manually.

       -x     Creates rid and primaryGroupID in hex instead of decimal (for 
              Samba 2.2.2 unpatched only - higher versions always use decimal)

       -A     can change password ? 0 if no, 1 if yes

       -B     must change password ? 0 if no, 1 if yes

       -C     sambaHomePath (SMB home share, like '\\\\PDC-SRV\\homes')

       -D     sambaHomeDrive (letter associated with home share, like 'H:')

       -E     sambaLogonScript, relative to the [netlogon] share (DOS script to execute on login, like 'foo.bat')

       -F     sambaProfilePath (profile directory, like '\\\\PDC-SRV\\profiles\\foo')

       -H     sambaAcctFlags, spaces and trailing bracket are ignored (samba account control bits like '[NDHTUMWSLKI]')

       -I     disable user. Can't be used with -H or -J

       -J     enable user. Can't be used with -H or -I

=head1 SEE ALSO

       usermod(1)

=cut

#'
