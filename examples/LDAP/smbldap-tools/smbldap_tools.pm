#! /usr/bin/perl
use strict;
package smbldap_tools;
use smbldap_conf;
use Net::LDAP;

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

#sub ldap_search
#{
#my ($local_base,$local_scope,$local_filtre)=@_;
#}



sub get_user_dn
{
    my $user = shift;
    my $dn='';
    my $ldap = Net::LDAP->new($slaveLDAP) or die "erreur LDAP";
    $ldap->bind ;
    my  $mesg = $ldap->search (    base   => $suffix,
				   scope => $scope,
				   filter => "(&(objectclass=posixAccount)(uid=$user))"
                              );
    $mesg->code && die $mesg->error;
    foreach my $entry ($mesg->all_entries) {
	$dn= $entry->dn;}
    $ldap->unbind;
    chomp($dn);
    if ($dn eq '') {
	return undef;
    }
    $dn="dn: ".$dn;
    return $dn;
}


sub get_user_dn2     ## migré
{
    my $user = shift;
    my $dn='';
    my $ldap = Net::LDAP->new($slaveLDAP) or die "erreur LDAP";
    $ldap->bind ;
    my  $mesg = $ldap->search (    base   => $suffix,
				   scope => $scope,
                               filter => "(&(objectclass=posixAccount)(uid=$user))"
                              );
    # $mesg->code && warn $mesg->error;
    if ($mesg->code)
      {
	  print("Code erreur : ",$mesg->code,"\n");
	  print("Message d'erreur : ",$mesg->error,"\n");
	  return (0,undef);
      }

    foreach my $entry ($mesg->all_entries) {
	$dn= $entry->dn;
    }
    $ldap->unbind;
    chomp($dn);
    if ($dn eq '') {
	return (1,undef);
    }
    $dn="dn: ".$dn;
    return (1,$dn);
}


sub get_group_dn
  {
      my $group = shift;
      my $dn='';
      my $ldap = Net::LDAP->new($slaveLDAP) or die "erreur LDAP";
      $ldap->bind ;
      my  $mesg = $ldap->search (    base   => $groupsdn,
				     scope => $scope,
				     filter => "(&(objectclass=posixGroup)(|(cn=$group)(gidNumber=$group)))"
				);
      $mesg->code && die $mesg->error;
      foreach my $entry ($mesg->all_entries) {
	  $dn= $entry->dn;}
      $ldap->unbind;
      chomp($dn);
      if ($dn eq '') {
	  return undef;
      }
      $dn="dn: ".$dn;
      return $dn;
  }

# return (success, dn)
# bool = is_samba_user($username)
sub is_samba_user
  {
      my $user = shift;
      my $ldap = Net::LDAP->new($slaveLDAP) or die "erreur LDAP";
      $ldap->bind ;
      my $mesg = $ldap->search (    base   => $suffix,
				    scope => $scope,
				    filter => "(&(objectClass=sambaSamAccount)(uid=$user))"
			       );
      $mesg->code && die $mesg->error;
      $ldap->unbind;
      return ($mesg->count ne 0);
  }


# try to bind with user dn and password to validate current password
sub is_user_valid
  {
      my ($user, $dn, $pass) = @_;
      my $ldap = Net::LDAP->new($slaveLDAP) or die "erreur LDAP";
      my $mesg= $ldap->bind (dn => $dn, password => $pass );
      if ($mesg->code eq 0)
	{
	    $ldap->unbind;
	    return 1;
	}
      else
	{
	    if($ldap->bind()) {
		$ldap->unbind;
		return 0;
	    } else {
		print ("Le serveur LDAP est indisponible.\nVérifier le serveur, les câblages, ...");
		$ldap->unbind;
		return 0;
	    } die "Problème : Contacter votre administrateur";
	}
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
objectclass: inetOrgPerson
objectclass: posixAccount
sn: $user
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
      my $sambaSID = 2 * $uid + 1000;
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
objectclass: inetOrgPerson
objectclass: posixAccount
objectClass: sambaSamAccount
sambaPwdLastSet: 0
sambaLogonTime: 0
sambaLogoffTime: 2147483647
sambaKickoffTime: 2147483647
sambaPwdCanChange: 0
sambaPwdMustChange: 2147483647
sambaAcctFlags: [W          ]
sambaLMPassword: $lmpassword
sambaNTPassword: $ntpassword
sambaSID: $smbldap_conf::SID-$sambaSID
sambaPrimaryGroupSID: $smbldap_conf::SID-0

";

      die "$0: error while adding samba account to $user\n"
	unless (do_ldapmodify($tmpldif) == 0);
      undef $tmpldif;

      return 1;
  }



sub group_add_user
  {
      my ($group, $userid) = @_;
      my $members='';
      my $dn_line = get_group_dn($group);
      if (!defined($dn_line)) {
	  return 1;
      }
      my $dn = get_dn_from_line($dn_line);

      my $ldap = Net::LDAP->new($slaveLDAP) or die "erreur LDAP";
      $ldap->bind ;
      my  $mesg = $ldap->search (    base   =>$dn, scope => "base", filter => "(objectClass=*)" );
      $mesg->code && die $mesg->error;
      foreach my $entry ($mesg->all_entries){
	  foreach my $attr ($entry->attributes)
	    {
		if ($attr=~/\bmemberUid\b/){
		    foreach my $ent($entry->get_value($attr)) { $members.= $attr.": ".$ent."\n"; }
		}
	    }
      }
      $ldap->unbind;
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

# XXX FIXME : sambaAcctFlags |= D, and not sambaAcctFlags = D
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
replace: sambaAcctFlags
sambaAcctFlags: [D       ]

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
      my $homeDir='';
      #  my $homeDir=`$ldapsearch -b '$suffix' -s '$scope' '(&(objectclass=posixAccount)(uid=$user))' | grep "^homeDirectory:"`;
      my $ldap = Net::LDAP->new($slaveLDAP) or die "erreur LDAP";
      $ldap->bind ;
      my  $mesg = $ldap->search (    base   =>$suffix, scope => $scope, filter => "(&(objectclass=posixAccount)(uid=$user))" );
      $mesg->code && die $mesg->error;
      foreach my $entry ($mesg->all_entries){
	  foreach my $attr ($entry->attributes)
	    {
		if ($attr=~/\bhomeDirectory\b/){
		    foreach my $ent($entry->get_value($attr)) {
			$homeDir.= $attr.": ".$ent."\n";
		    }
		}
	    }
      }
      $ldap->unbind;
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
      my $lines ='';
      my $ldap = Net::LDAP->new($slaveLDAP) or die "erreur LDAP";
      $ldap->bind ;
      my  $mesg = $ldap->search (  # perform a search
				 base   => $suffix,
				 scope => $scope,
				 filter => "(&(objectclass=posixAccount)(uid=$user))"
				);

      $mesg->code && die $mesg->error;
      foreach my $entry ($mesg->all_entries) {
	  $lines.= "dn: " . $entry->dn."\n";
	  foreach my $attr ($entry->attributes) {
	      {
		  $lines.= $attr.": ".join(',', $entry->get_value($attr))."\n";
	      }
	  }
      }
      $ldap->unbind;   # take down sessio(n
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
      my $lines ='';
      my $ldap = Net::LDAP->new($slaveLDAP) or die "erreur LDAP";
      $ldap->bind ;
      my  $mesg = $ldap->search (  # perform a search
				 base   => $groupsdn,
				 scope => $scope,
				 filter => "(&(objectclass=posixGroup)(cn=$user))"
				);

      $mesg->code && die $mesg->error;
      foreach my $entry ($mesg->all_entries) {
	  $lines.= "dn: " . $entry->dn."\n";
	  foreach my $attr ($entry->attributes) {
	      {
		  $lines.= $attr.": ".join(',', $entry->get_value($attr))."\n";
	      }
	  }
      }

      $ldap->unbind;   # take down sessio(n
      chomp $lines;
      if ($lines eq '') {
	  return undef;
      }
      return $lines;
  }

# find groups of a given user
##### MODIFIE ########
sub find_groups_of
  {
      my $user = shift;
      my $lines ='';
      my $ldap = Net::LDAP->new($slaveLDAP) or die "erreur LDAP";
      $ldap->bind ;
      my  $mesg = $ldap->search (  # perform a search
				 base   => $groupsdn,
				 scope => $scope,
				 filter => "(&(objectclass=posixGroup)(memberuid=$user))"
				);
      $mesg->code && die $mesg->error;
      foreach my $entry ($mesg->all_entries) {
	  $lines.= "dn: ".$entry->dn."\n";
      }
      $ldap->unbind;
      chomp($lines);
      if ($lines eq '') {return undef; }
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
      my $members='';
      my $grp_line = get_group_dn($group);
      if (!defined($grp_line)) {
	  return 0;
      }

      my $ldap = Net::LDAP->new($slaveLDAP) or die "erreur LDAP";
      $ldap->bind ;
      my  $mesg = $ldap->search (    base   => $groupsdn,
				     scope => $scope,
				     filter => "(&(objectclass=posixgroup)(cn=$group))"
				);
      $mesg->code && die $mesg->error;
      foreach my $entry ($mesg->all_entries){
	  foreach my $attr ($entry->attributes)
	    {
		if ($attr=~/\bmemberUid\b/){
		    foreach my $ent($entry->get_value($attr)) {
			$members.= $attr.": ".$ent."\n";
		    }
		}
	    }
      }
      #print "Valeurs de members :\n$members";
      $ldap->unbind;
      #    my $members = `$ldapsearch -b '$groupsdn' -s '$scope' '(&(objectclass=posixgroup)(cn=$group))' | grep -i "^memberUid:"`;
      # print "avant ---\n$members\n";
      $members =~ s/memberUid: $user\n//;
      #print "après ---\n$members\n";
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

      #print "Valeur du tmpldif : \n$tmpldif";
      die "$0: error while modifying group $group\n"
	unless (do_ldapmodify($tmpldif) == 0);
      undef $tmpldif;

      $ldap->unbind;
      return 1;
  }

sub group_get_members
  {
      my ($group) = @_;
      my $members;
      my @resultat;
      my $grp_line = get_group_dn($group);
      if (!defined($grp_line)) {	return 0;  }

      my $ldap = Net::LDAP->new($slaveLDAP) or die "erreur LDAP";
      $ldap->bind ;
      my  $mesg = $ldap->search (    base   => $groupsdn,
				     scope => $scope,
				     filter => "(&(objectclass=posixgroup)(cn=$group))"
				);
      $mesg->code && die $mesg->error;
      foreach my $entry ($mesg->all_entries){
	  foreach my $attr ($entry->attributes){
	      if ($attr=~/\bmemberUid\b/){
		  foreach my $ent($entry->get_value($attr)) { push (@resultat,$ent); }
	      }
	  }
      }
      return @resultat;
  }

sub file_write {
    my ($filename, $filecontent) = @_;
    local *FILE;
    open (FILE, "> $filename") ||
      die "Cannot open $filename for writing: $!\n";
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

