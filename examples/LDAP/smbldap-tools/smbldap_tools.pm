#! /usr/bin/perl -w
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
			 is_group_member
			 is_samba_user
			 is_unix_user
			 is_user_valid
			 does_sid_exist
			 get_dn_from_line
			 add_posix_machine
			 add_samba_machine
			 add_samba_machine_mkntpwd
			 group_add_user
			 add_grouplist_user
			 disable_user
			 delete_user
			 group_add
			 group_del
			 get_homedir
			 read_user
			 read_user_entry
			 read_group
			 read_group_entry
			 read_group_entry_gid
			 find_groups_of
			 parse_group
			 group_remove_member
			 group_get_members
			 do_ldapadd
			 do_ldapmodify
			 get_user_dn2
			 connect_ldap_master
			 connect_ldap_slave
			 group_type_by_name
			);

sub connect_ldap_master
  {
	# bind to a directory with dn and password
	my $ldap_master = Net::LDAP->new(
									 "$masterLDAP",
									 port => "$masterPort",
									 version => 3,
									 # debug => 0xffff,
									)
	  or die "erreur LDAP: Can't contact master ldap server ($@)";
	if ($ldapSSL == 1) {
	  $ldap_master->start_tls(
							  # verify => 'require',
							  # clientcert => 'mycert.pem',
							  # clientkey => 'mykey.pem',
							  # decryptkey => sub { 'secret'; },
							  # capath => '/usr/local/cacerts/'
							 );
	}
	$ldap_master->bind ( "$binddn",
						 password => "$masterPw"
					   );
	return($ldap_master);
  }

sub connect_ldap_slave
  {
	# bind to a directory with dn and password
	my $ldap_slave = Net::LDAP->new(
									"$slaveLDAP",
									port => "$slavePort",
									version => 3,
									# debug => 0xffff,
								   )
	  or die "erreur LDAP: Can't contact slave ldap server ($@)";
	if ($ldapSSL == 1) {
	  $ldap_slave->start_tls(
							 # verify => 'require',
							 # clientcert => 'mycert.pem',
							 # clientkey => 'mykey.pem',
							 # decryptkey => sub { 'secret'; },
							 # capath => '/usr/local/cacerts/'
							);
	}
	$ldap_slave->bind ( "$binddn",
						password => "$slavePw"
					  );
	return($ldap_slave);
  }

sub get_user_dn
  {
    my $user = shift;
    my $dn='';
    my $ldap_slave=connect_ldap_slave();
    my  $mesg = $ldap_slave->search (    base   => $suffix,
										 scope => $scope,
										 filter => "(&(objectclass=posixAccount)(uid=$user))"
									);
    $mesg->code && die $mesg->error;
    foreach my $entry ($mesg->all_entries) {
	  $dn= $entry->dn;
	}
    $ldap_slave->unbind;
    chomp($dn);
    if ($dn eq '') {
	  return undef;
    }
    $dn="dn: ".$dn;
    return $dn;
  }


sub get_user_dn2
  {
    my $user = shift;
    my $dn='';
    my $ldap_slave=connect_ldap_slave();
    my  $mesg = $ldap_slave->search (    base   => $suffix,
										 scope => $scope,
										 filter => "(&(objectclass=posixAccount)(uid=$user))"
									);
    $mesg->code && warn "failed to perform search; ", $mesg->error;

    foreach my $entry ($mesg->all_entries) {
	  $dn= $entry->dn;
    }
    $ldap_slave->unbind;
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
	my $ldap_slave=connect_ldap_slave();
	my  $mesg = $ldap_slave->search (    base   => $groupsdn,
										 scope => $scope,
										 filter => "(&(objectclass=posixGroup)(|(cn=$group)(gidNumber=$group)))"
									);
	$mesg->code && die $mesg->error;
	foreach my $entry ($mesg->all_entries) {
	  $dn= $entry->dn;
	}
	$ldap_slave->unbind;
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
	my $ldap_slave=connect_ldap_slave();
	my $mesg = $ldap_slave->search (    base   => $suffix,
										scope => $scope,
										filter => "(&(objectClass=sambaSamAccount)(uid=$user))"
								   );
	$mesg->code && die $mesg->error;
	$ldap_slave->unbind;
	return ($mesg->count ne 0);
  }

sub is_unix_user
  {
	my $user = shift;
	my $ldap_slave=connect_ldap_slave();
	my $mesg = $ldap_slave->search (    base   => $suffix,
										scope => $scope,
										filter => "(&(objectClass=posixAccount)(uid=$user))"
								   );
	$mesg->code && die $mesg->error;
	$ldap_slave->unbind;
	return ($mesg->count ne 0);
  }

sub is_group_member
  {
	my $dn_group = shift;
	my $user = shift;
	my $ldap_slave=connect_ldap_slave();
	my $mesg = $ldap_slave->search (   base   => $dn_group,
									scope => 'base',
									filter => "(&(memberUid=$user))"
								   );
	$mesg->code && die $mesg->error;
	$ldap_slave->unbind;
	return ($mesg->count ne 0);
  }

# all entries = does_sid_exist($sid,$scope)
sub does_sid_exist
  {
	my $sid = shift;
	my $dn_group=shift;
	my $ldap_slave=connect_ldap_slave();
	my $mesg = $ldap_slave->search (    base   => $dn_group,
										scope => $scope,
										filter => "(sambaSID=$sid)"
										#filter => "(&(objectClass=sambaSamAccount|objectClass=sambaGroupMapping)(sambaSID=$sid))"
								   );
	$mesg->code && die $mesg->error;
	$ldap_slave->unbind;
	return ($mesg);
  }

# try to bind with user dn and password to validate current password
sub is_user_valid
  {
	my ($user, $dn, $pass) = @_;
	my $ldap = Net::LDAP->new($slaveLDAP) or die "erreur LDAP";
	my $mesg= $ldap->bind (dn => $dn, password => $pass );
	if ($mesg->code eq 0) {
	  $ldap->unbind;
	  return 1;
	} else {
	  if ($ldap->bind()) {
		$ldap->unbind;
		return 0;
	  } else {
		print ("The LDAP directory is not available.\n Check the server, cables ...");
		$ldap->unbind;
		return 0;
	  }
	  die "Problem : contact your administrator";
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
	# bind to a directory with dn and password
	my $ldap_master=connect_ldap_master();
	my $add = $ldap_master->add ( "uid=$user,$computersdn",
								  attr => [
										   'objectclass' => ['top','inetOrgPerson', 'posixAccount'],
										   'cn'   => "$user",
										   'sn'   => "$user",
										   'uid'   => "$user",
										   'uidNumber'   => "$uid",
										   'gidNumber'   => "$gid",
										   'homeDirectory'   => '/dev/null',
										   'loginShell'   => '/bin/false',
										   'description'   => 'Computer',
										  ]
								);
	
	$add->code && warn "failed to add entry: ", $add->error ;
	# take down the session
	$ldap_master->unbind;

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

	my $ldap_master=connect_ldap_master();
	my $modify = $ldap_master->modify ( "uid=$user,$computersdn",
										changes => [
													replace => [objectClass => ['inetOrgPerson', 'posixAccount', 'sambaSamAccount']],
													add => [sambaPwdLastSet => '0'],
													add => [sambaLogonTime => '0'],
													add => [sambaLogoffTime => '2147483647'],
													add => [sambaKickoffTime => '2147483647'],
													add => [sambaPwdCanChange => '0'],
													add => [sambaPwdMustChange => '0'],
													add => [sambaAcctFlags => '[W          ]'],
													add => [sambaLMPassword => "$lmpassword"],
													add => [sambaNTPassword => "$ntpassword"],
													add => [sambaSID => "$SID-$sambaSID"],
													add => [sambaPrimaryGroupSID => "$SID-0"]
												   ]
									  );
	
	$modify->code && die "failed to add entry: ", $modify->error ;

	return 1;
	# take down the session
	$ldap_master->unbind;

  }


sub group_add_user
  {
	my ($group, $userid) = @_;
	my $members='';
	my $dn_line = get_group_dn($group);
	if (!defined(get_group_dn($group))) {
	  print "$0: group \"$group\" doesn't exist\n";
	  exit (6); 
	}
	if (!defined($dn_line)) {
	  return 1;
	}
	my $dn = get_dn_from_line("$dn_line");
	# on look if the user is already present in the group
	my $is_member=is_group_member($dn,$userid);
	if ($is_member == 1) {
	  print "User \"$userid\" already member of the group \"$group\".\n";
	} else {
	  # bind to a directory with dn and password
	  my $ldap_master=connect_ldap_master();
	  # It does not matter if the user already exist, Net::LDAP will add the user
	  # if he does not exist, and ignore him if his already in the directory.
	  my $modify = $ldap_master->modify ( "$dn",
										  changes => [
													  add => [memberUid => $userid]
													 ]
										);
	  $modify->code && die "failed to modify entry: ", $modify->error ;
	  # take down session
	  $ldap_master->unbind;
	}
  }

sub group_del
  {
	my $group_dn=shift;
	# bind to a directory with dn and password
	my $ldap_master=connect_ldap_master();
	my $modify = $ldap_master->delete ($group_dn);
	$modify->code && die "failed to delete group : ", $modify->error ;
	# take down session
	$ldap_master->unbind;
  }

sub add_grouplist_user
  {
	my ($grouplist, $user) = @_;
	my @array = split(/,/, $grouplist);
	foreach my $group (@array) {
	  group_add_user($group, $user);
	}
  }

sub disable_user
  {
	my $user = shift;
	my $dn_line;
	my $dn = get_dn_from_line($dn_line);
	
	if (!defined($dn_line = get_user_dn($user))) {
	  print "$0: user $user doesn't exist\n";
	  exit (10);
	}
	my $ldap_master=connect_ldap_master();
	my $modify = $ldap_master->modify ( "$dn",
										changes => [
													replace => [userPassword => '{crypt}!x']
												   ]
									  );
	$modify->code && die "failed to modify entry: ", $modify->error ;

	if (is_samba_user($user)) {
	  my $modify = $ldap_master->modify ( "$dn",
										  changes => [
													  replace => [sambaAcctFlags => '[D       ]']
													 ]
										);
	  $modify->code && die "failed to modify entry: ", $modify->error ;
	}
	# take down session
	$ldap_master->unbind;
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
	my $ldap_master=connect_ldap_master();
	my $modify = $ldap_master->delete($dn);
	$ldap_master->unbind;
  }

# $gid = group_add($groupname, $group_gid, $force_using_existing_gid)
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
		  return undef;
		}
	  }
	}
	if ($nscd_status == 0) {
	  system "/etc/init.d/nscd start > /dev/null 2>&1";
	}
	my $ldap_master=connect_ldap_master();
	my $modify = $ldap_master->add ( "cn=$gname,$groupsdn",
									 attrs => [
											   objectClass => 'posixGroup',
											   cn => "$gname",
											   gidNumber => "$gid"
											  ]
								   );
	
	$modify->code && die "failed to add entry: ", $modify->error ;
	# take down session
	$ldap_master->unbind;
	return $gid;
  }

# $homedir = get_homedir ($user)
sub get_homedir
  {
	my $user = shift;
	my $homeDir='';
	my $ldap_slave=connect_ldap_slave();
	my  $mesg = $ldap_slave->search (
									 base   =>$suffix,
									 scope => $scope,
									 filter => "(&(objectclass=posixAccount)(uid=$user))"
									);
	$mesg->code && die $mesg->error;
	foreach my $entry ($mesg->all_entries) {
	  foreach my $attr ($entry->attributes) {
		if ($attr=~/\bhomeDirectory\b/) {
		  foreach my $ent ($entry->get_value($attr)) {
			$homeDir.= $attr.": ".$ent."\n";
		  }
		}
	  }
	}
	$ldap_slave->unbind;
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
	my $ldap_slave=connect_ldap_slave();
	my $mesg = $ldap_slave->search ( # perform a search
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
	# take down session
	$ldap_slave->unbind;
	chomp $lines;
	if ($lines eq '') {
	  return undef;
	}
	return $lines;
  }

# search for a user
# return the attributes in an array
sub read_user_entry
  {
	my $user = shift;
	my $ldap_slave=connect_ldap_slave();
	my  $mesg = $ldap_slave->search ( # perform a search
									 base   => $suffix,
									 scope => $scope,
									 filter => "(&(objectclass=posixAccount)(uid=$user))"
									);

	$mesg->code && die $mesg->error;
	my $entry = $mesg->entry();
	$ldap_slave->unbind;
	return $entry;
  }

# search for a group
sub read_group
  {
	my $user = shift;
	my $lines ='';
	my $ldap_slave=connect_ldap_slave();
	my  $mesg = $ldap_slave->search ( # perform a search
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
	# take down session
	$ldap_slave->unbind;
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
	my $ldap_slave=connect_ldap_slave;
	my  $mesg = $ldap_slave->search ( # perform a search
									 base   => $groupsdn,
									 scope => $scope,
									 filter => "(&(objectclass=posixGroup)(memberuid=$user))"
									);
	$mesg->code && die $mesg->error;
	foreach my $entry ($mesg->all_entries) {
	  $lines.= "dn: ".$entry->dn."\n";
	}
	$ldap_slave->unbind;
	chomp($lines);
	if ($lines eq '') {
	  return undef;
	}
	return $lines;
  }

sub read_group_entry {
  my $group = shift;
  my $entry;
  my %res;
  my $ldap_slave=connect_ldap_slave();
  my  $mesg = $ldap_slave->search ( # perform a search
								   base   => $groupsdn,
								   scope => $scope,
								   filter => "(&(objectclass=posixGroup)(cn=$group))"
								  );

  $mesg->code && die $mesg->error;
  my $nb=$mesg->count;
  if ($nb > 1) {
    print "Error: $nb groups exist \"cn=$group\"\n";
    foreach $entry ($mesg->all_entries) { my $dn=$entry->dn; print "  $dn\n"; }
    exit 11;
  } else {
    $entry = $mesg->shift_entry();
  }
  return $entry;
}

sub read_group_entry_gid {
  my $group = shift;
  my %res;
  my $ldap_slave=connect_ldap_slave();
  my  $mesg = $ldap_slave->search ( # perform a search
                                  base   => $groupsdn,
                                  scope => $scope,
                                  filter => "(&(objectclass=posixGroup)(gidNumber=$group))"
                                 );

  $mesg->code && die $mesg->error;
  my $entry = $mesg->shift_entry();
  return $entry;
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
	my $dn = get_dn_from_line($grp_line);
	# we test if the user exist in the group
	my $is_member=is_group_member($dn,$user);
	if ($is_member == 1) {
	  my $ldap_master=connect_ldap_master();
	  # delete only the user from the group
	  my $modify = $ldap_master->modify ( "$dn",
										  changes => [
													  delete => [memberUid => ["$user"]]
													 ]
										);
	  $modify->code && die "failed to delete entry: ", $modify->error ;
	  $ldap_master->unbind;
	}
	return 1;
  }

sub group_get_members
  {
	my ($group) = @_;
	my $members;
	my @resultat;
	my $grp_line = get_group_dn($group);
	if (!defined($grp_line)) {
	  return 0;
	}

	my $ldap = Net::LDAP->new($slaveLDAP) or die "erreur LDAP";
	$ldap->bind ;
	my  $mesg = $ldap->search (
							   base   => $groupsdn,
							   scope => $scope,
							   filter => "(&(objectclass=posixgroup)(cn=$group))"
							  );
	$mesg->code && die $mesg->error;
	foreach my $entry ($mesg->all_entries) {
	  foreach my $attr ($entry->attributes) {
		if ($attr=~/\bmemberUid\b/) {
		  foreach my $ent ($entry->get_value($attr)) {
			push (@resultat,$ent);
		  }
		}
	  }
	}
	return @resultat;
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

sub group_type_by_name {
  my $type_name = shift;
  my %groupmap = (
    'domain' => 2,
    'local' => 4,
    'builtin' => 5
  );
  return $groupmap{$type_name};
}



1;

