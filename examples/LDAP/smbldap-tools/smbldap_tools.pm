#! /usr/bin/perl
use strict;
package smbldap_tools;
use smbldap_conf;

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


# ugly funcs using global variables and spawning openldap clients

use vars       qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);
use Exporter;
$VERSION = 1.00;
@ISA = qw(Exporter);

@EXPORT = qw(
get_user_dn
get_group_dn
is_samba_user
is_user_valid
get_dn_from_line
add_posix_machine
add_samba_machine
add_samba_machine_mkntpwd
group_add_user
add_grouplist_user
disable_user
delete_user
group_add
get_homedir
read_user
read_group
find_groups_of
parse_group
group_remove_member
group_get_members
do_ldapadd
do_ldapmodify
get_user_dn2
);

# dn_line = get_user_dn($username)
# where dn_line is like "dn: a=b,c=d"
sub get_user_dn
{
    my $user = shift;
    my $dn=`$ldapsearch -b '$suffix' -s '$scope' '(&(objectclass=posixAccount)(uid=$user))' | grep "^dn:"`;
    chomp $dn;
    if ($dn eq '') {
	return undef;
    }
    
    return $dn;
}

# return (success, dn)
sub get_user_dn2
{
    my $user = shift;

    my $sr = `$ldapsearch -b '$suffix' -s '$scope' '(&(objectclass=posixAccount)(uid=$user))'`;
    if ($sr eq "") {
	print "get_user_dn2: error in ldapsearch :
$ldapsearch -b '$suffix' -s '$scope' '(&(objectclass=posixAccount)(uid=$user))'\n";
	return (0, undef);
    }

    my @lines = split(/\n/, $sr);

    my @matches = grep(/^dn:/, @lines);

    my $dn = $matches[0];
    chomp $dn;
    if ($dn eq '') {
	return (1, undef);
    }
    
    return (1, $dn);
}

# dn_line = get_group_dn($groupname)
# where dn_line is like "dn: a=b,c=d"
sub get_group_dn
{
    my $group = shift;
    my $dn=`$ldapsearch -b '$groupsdn' -s '$scope' '(&(objectclass=posixGroup)(|(cn=$group)(gidNumber=$group)))' | grep "^dn:"`;
    chomp $dn;
    if ($dn eq '') {
	return undef;
    }
    
    return $dn;
}

# bool = is_samba_user($username)
sub is_samba_user
{
    my $user = shift;
    my $cmd = "$ldapsearch -b '$suffix' -s '$scope' '(&(objectClass=sambaAccount)(uid=$user))' | grep '^dn:\'";
    my $res=`$cmd`;
    chomp $res;
    if ($res ne '') {
	return 1;
    }
    return 0;
}

# bool = is_user_valid($username)
# try to bind with user dn and password to validate current password
sub is_user_valid 
{
    my ($user, $dn, $pass) = @_;
    my $res=`$ldapsearchnobind -b '$usersdn' -s '$scope' -D '$dn' -w '$pass' '(&(objectclass=posixAccount)(uid=$user))' 2>/dev/null | grep "^dn:"`;
    chomp $res;
    if ($res eq '') {
	return 0;
    }
    return 1;
}

# dn = get_dn_from_line ($dn_line)
# helper to get "a=b,c=d" from "dn: a=b,c=d"
sub get_dn_from_line
{
    my $dn = shift;
    $dn =~ s/^dn: //;
    return $dn;
}

# success = add_posix_machine($user, $uid, $gid)
sub add_posix_machine
{
    my ($user, $uid, $gid) = @_;

my $tmpldif =
"dn: uid=$user,$computersdn
objectclass: top
objectclass: posixAccount
cn: $user
uid: $user
uidNumber: $uid
gidNumber: $gid
homeDirectory: /dev/null
loginShell: /bin/false
description: Computer

";

    die "$0: error while adding posix account to machine $user\n"
	unless (do_ldapadd($tmpldif) == 0);
    
    undef $tmpldif;

    return 1;
}

# success = add_samba_machine($computername)
sub add_samba_machine
{
    my $user = shift;
    system "smbpasswd -a -m $user";
    
    return 1;
}

sub add_samba_machine_mkntpwd
{
    my ($user, $uid) = @_;
    my $rid = 2 * $uid + 1000; # Samba 2.2.2 stuff

    my $name = $user;
    $name =~ s/.$//s;

    if ($mk_ntpasswd eq '') {
	print "Either set \$with_smbpasswd = 1 or specify \$mk_ntpasswd\n";
	return 0;
    }

    my $ntpwd = `$mk_ntpasswd '$name'`;
    chomp(my $lmpassword = substr($ntpwd, 0, index($ntpwd, ':')));
    chomp(my $ntpassword = substr($ntpwd, index($ntpwd, ':')+1));

    my $tmpldif =
"dn: uid=$user,$computersdn
changetype: modify
objectclass: top
objectclass: posixAccount
objectClass: sambaAccount
pwdLastSet: 0
logonTime: 0
logoffTime: 2147483647
kickoffTime: 2147483647
pwdCanChange: 0
pwdMustChange: 2147483647
acctFlags: [W          ]
lmpassword: $lmpassword
ntpassword: $ntpassword
rid: $rid
primaryGroupID: 0

";

    die "$0: error while adding samba account to $user\n"
	    unless (do_ldapmodify($tmpldif) == 0);
    undef $tmpldif;

    return 1;
}



sub group_add_user
{
    my ($group, $userid) = @_;
    my $dn_line;

    if (!defined($dn_line = get_group_dn($group))) {
	return 1;
    }
    my $dn = get_dn_from_line($dn_line);
    my $members = `$ldapsearch -b '$dn' -s base | grep -i "^memberUid:"`;
    chomp($members);
    # user already member ?
    if ($members =~ m/^memberUid: $userid/) {
	return 2;
    }
    my $mods = "";
    if ($members ne '') {
	$mods="$dn_line
changetype: modify
replace: memberUid
$members
memberUid: $userid
";
    } else {
	$mods="$dn_line
changetype: modify
add: memberUid
memberUid: $userid
";
    }

    #print "$mods\n";

    my $tmpldif =
"$mods
";

    die "$0: error while modifying group $group\n"
	unless (do_ldapmodify($tmpldif) == 0);
    undef $tmpldif;
    return 0;
}

sub add_grouplist_user 
{
    my ($grouplist, $user) = @_;
    my @array = split(/,/, $grouplist);
    foreach my $group (@array) {
	group_add_user($group, $user);
    }
}

# XXX FIXME : acctFlags |= D, and not acctFlags = D
sub disable_user
{
    my $user = shift;
    my $dn_line;

    if (!defined($dn_line = get_user_dn($user))) {
	print "$0: user $user doesn't exist\n";
	exit (10);
    }

    my $tmpldif =
"dn: $dn_line
changetype: modify
replace: userPassword
userPassword: {crypt}!x

";

    die "$0: error while modifying user $user\n"
	unless (do_ldapmodify($tmpldif) == 0);
    undef $tmpldif;

    if (is_samba_user($user)) {
	    
	my $tmpldif =
"dn: $dn_line
changetype: modify
replace: acctFlags
acctFlags: [D       ]

";

	die "$0: error while modifying user $user\n"
	    unless (do_ldapmodify($tmpldif) == 0);
	undef $tmpldif;

    }
 
}

# delete_user($user)
sub delete_user
{
    my $user = shift;
    my $dn_line;

    if (!defined($dn_line = get_user_dn($user))) {
	print "$0: user $user doesn't exist\n";
	exit (10);
    }

    my $dn = get_dn_from_line($dn_line);
    system "$ldapdelete $dn >/dev/null";
}

# $success = group_add($groupname, $group_gid, $force_using_existing_gid)
sub group_add
{
    my ($gname, $gid, $force) = @_;

    my $nscd_status = system "/etc/init.d/nscd status >/dev/null 2>&1";

    if ($nscd_status == 0) {
       system "/etc/init.d/nscd stop > /dev/null 2>&1";
    }

    if (!defined($gid)) {
	while (defined(getgrgid($GID_START))) {
	    $GID_START++;
	}
	$gid = $GID_START;
    } else {
	if (!defined($force)) {
	    if (defined(getgrgid($gid))) {
		return 0;
	    }
	}
    }

    if ($nscd_status == 0) {
       system "/etc/init.d/nscd start > /dev/null 2>&1";
    }

    my $tmpldif =
"dn: cn=$gname,$groupsdn
objectclass: posixGroup
cn: $gname
gidNumber: $gid

";

    die "$0: error while adding posix group $gname\n"
	unless (do_ldapadd($tmpldif) == 0);

    undef $tmpldif;

    return 1;
}

# $homedir = get_homedir ($user)
sub get_homedir
{
    my $user = shift;
    my $homeDir=`$ldapsearch -b '$suffix' -s '$scope' '(&(objectclass=posixAccount)(uid=$user))' | grep "^homeDirectory:"`;
    chomp $homeDir;
    if ($homeDir eq '') {
	return undef;
    }
    $homeDir =~ s/^homeDirectory: //;

    return $homeDir;
}

# search for an user
sub read_user
{
    my $user = shift;
    my $lines=`$ldapsearch -b '$suffix' -s '$scope' '(&(objectclass=posixAccount)(uid=$user))' -LLL`;
    chomp $lines;
    if ($lines eq '') {
	return undef;
    }

    return $lines;
}

# search for a group
sub read_group
{
    my $user = shift;
    my $lines=`$ldapsearch -b '$groupsdn' -s '$scope' '(&(objectclass=posixGroup)(cn=$user))' -LLL`;
    chomp $lines;
    if ($lines eq '') {
	return undef;
    }

    return $lines;
}

# find groups of a given user
sub find_groups_of
{
    my $user = shift;
    my $lines=`$ldapsearch -b '$groupsdn' -s '$scope' '(&(objectclass=posixGroup)(memberuid=$user))' -LLL | grep "^dn: "`;
    chomp $lines;
    if ($lines eq '') {
	return undef;
    }

    return $lines;
}

# return the gidnumber for a group given as name or gid
# -1 : bad group name
# -2 : bad gidnumber
sub parse_group
{
    my $userGidNumber = shift;

    if ($userGidNumber =~ /[^\d]/ ) {
	my $gname = $userGidNumber;
	my $gidnum = getgrnam($gname);
	if ($gidnum !~ /\d+/) {
	    return -1;
	} else {
	    $userGidNumber = $gidnum;
	}
    } elsif (!defined(getgrgid($userGidNumber))) {
	return -2;
    }
    return $userGidNumber;
}

# remove $user from $group
sub group_remove_member
{
    my ($group, $user) = @_;

    my $grp_line = get_group_dn($group);
    if (!defined($grp_line)) {
	return 0;
    }
    my $members = `$ldapsearch -b '$groupsdn' -s '$scope' '(&(objectclass=posixgroup)(cn=$group))' | grep -i "^memberUid:"`;

    #print "avant ---\n$members\n";
    $members =~ s/memberUid: $user\n//;
    #print "----\n$members\n---\n";

    chomp($members);

    my $header;
    if ($members eq '') {
	$header = "changetype: modify\n";
	$header .= "delete: memberUid";
    } else {
	$header = "changetype: modify\n";
	$header .= "replace: memberUid";
    }

    my $tmpldif =
"$grp_line
$header
$members
";
    die "$0: error while modifying group $group\n"
	unless (do_ldapmodify($tmpldif) == 0);
    undef $tmpldif;

    return 1;
}

sub group_get_members
{
    my ($group) = @_;
    my @members;

    my $grp_line = get_group_dn($group);
    if (!defined($grp_line)) {
	return 0;
    }
    my $members = `$ldapsearch -b '$groupsdn' -s '$scope' '(&(objectclass=posixgroup)(cn=$group))' memberUid | grep -i "^memberUid:"`;

    my @lines = split (/\n/, $members);
    foreach my $line (@lines) {
	$line =~ s/^memberUid: //;
	push(@members, $line);
    }

    return @members;
}

sub file_write {
  my ($filename, $filecontent) = @_;
  local *FILE;
  open (FILE, "> $filename") ||
    die "Cannot open «$filename» for writing: $!\n";
  print FILE $filecontent;
  close FILE;
}

# wrapper for ldapadd
sub do_ldapadd2
{
    my $ldif = shift;

    my $tempfile = "/tmp/smbldapadd.$$";
    file_write($tempfile, $ldif);

    my $rc = system "$ldapadd < $tempfile >/dev/null";
    unlink($tempfile);
    return $rc;
}

sub do_ldapadd
{
    my $ldif = shift;

    my $FILE = "|$ldapadd >/dev/null";
    open (FILE, $FILE) || die "$!\n";
    print FILE <<EOF;
$ldif
EOF
    ;
    close FILE;
    my $rc = $?;
    return $rc;
}

# wrapper for ldapmodify
sub do_ldapmodify2
{
    my $ldif = shift;

    my $tempfile = "/tmp/smbldapmod.$$";
    file_write($tempfile, $ldif);

    my $rc = system "$ldapmodify -r < $tempfile >/dev/null";
    unlink($tempfile);
    return $rc;
}

sub do_ldapmodify
{
    my $ldif = shift;

    my $FILE = "|$ldapmodify -r >/dev/null";
    open (FILE, $FILE) || die "$!\n";
    print FILE <<EOF;
$ldif
EOF
    ;
    close FILE;
    my $rc = $?;

    return $rc;
}



1;

