#!/usr/bin/perl -w

#  This code was developped by IDEALX (http://IDEALX.org/) and
#  contributors (their names can be found in the CONTRIBUTORS file).
#
#                 Copyright (C) 2002 IDEALX
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

# Purpose of smbldap-useradd : user (posix,shadow,samba) add

use strict;

use FindBin;
use FindBin qw($RealBin);
use lib "$RealBin/";
use smbldap_tools;
use smbldap_conf;

#####################

use Getopt::Std;
my %Options;

my $ok = getopts('anmwPG:u:g:d:s:c:k:A:B:C:D:E:F:H:N:S:?', \%Options);

if ( (!$ok) || (@ARGV < 1) || ($Options{'?'}) ) {
  print "Usage: $0 [-awmugdsckGPABCDEFH?] username\n";
  print "  -a	is a Windows User (otherwise, Posix stuff only)\n";
  print "  -w	is a Windows Workstation (otherwise, Posix stuff only)\n";
  print "  -u	uid\n";
  print "  -g	gid\n";
  print "  -G	supplementary comma-separated groups\n";
  print "  -n	do not create a group\n";
  print "  -d	home\n";
  print "  -s	shell\n";
  print "  -c	gecos\n";
  print "  -m	creates home directory and copies /etc/skel\n";
  print "  -k	skeleton dir (with -m)\n";
  print "  -P	ends by invoking smbldap-passwd.pl\n";
  print "  -A	can change password ? 0 if no, 1 if yes\n";
  print "  -B	must change password ? 0 if no, 1 if yes\n";
  print "  -C	sambaHomePath (SMB home share, like '\\\\PDC-SRV\\homes')\n";
  print "  -D	sambaHomeDrive (letter associated with home share, like 'H:')\n";
  print "  -E	sambaLogonScript (DOS script to execute on login)\n";
  print "  -F	sambaProfilePath (profile directory, like '\\\\PDC-SRV\\profiles\\foo')\n";
  print "  -H	sambaAcctFlags (samba account control bits like '[NDHTUMWSLKI]')\n";
  print "  -N	canonical name\n";
  print "  -S	surname\n";
  print "  -?	show this help message\n";
  exit (1);
}


# cause problems when dealing with getpwuid because of the
# negative ttl and ldap modification
my $nscd_status = system "/etc/init.d/nscd status >/dev/null 2>&1";

if ($nscd_status == 0) {
  system "/etc/init.d/nscd stop > /dev/null 2>&1";
}


# Read options
my $userUidNumber = $Options{'u'};
if (!defined($userUidNumber)) { 
  # find first unused uid starting from $UID_START
  while (defined(getpwuid($UID_START))) {
	$UID_START++;
  }
  $userUidNumber = $UID_START;
} elsif (getpwuid($userUidNumber)) {
  die "Uid already exists.\n";
}

if ($nscd_status == 0) {
  system "/etc/init.d/nscd start > /dev/null 2>&1";
}


my $createGroup = 0;
my $userGidNumber = $Options{'g'};
# gid not specified ? 
if (!defined($userGidNumber)) {
  # windows machine => $_defaultComputerGid
  if (defined($Options{'w'})) {
	$userGidNumber = $_defaultComputerGid;
	#    } elsif (!defined($Options{'n'})) {
	# create new group (redhat style)
	# find first unused gid starting from $GID_START
	#	while (defined(getgrgid($GID_START))) {
	#		$GID_START++;
	#	}
	#	$userGidNumber = $GID_START;

	#	$createGroup = 1;

  } else {
	# user will have gid = $_defaultUserGid
	$userGidNumber = $_defaultUserGid;
  }
} else {
  my $gid;
  if (($gid = parse_group($userGidNumber)) < 0) {
	print "$0: unknown group $userGidNumber\n";
	exit (6);
  }
  $userGidNumber = $gid;
}

# Read only first @ARGV
my $userName = $ARGV[0];

# untaint $userName (can finish with one or two $)
if ($userName =~ /^([\w -]+\$?)$/) {
  $userName = $1;
} else {
  print "$0: illegal username\n";
  exit (1);
}

# user must not exist in LDAP (should it be nss-wide ?)
my ($rc, $dn) = get_user_dn2($userName);
if ($rc and defined($dn)) {
  print "$0: user $userName exists\n";
  exit (9);
} elsif (!$rc) {
  print "$0: error in get_user_dn2\n";
  exit(10);
}

my $group_entry;
my $userGroupSID;
my $userRid;
if ($Options{'a'}) {
	# as grouprid we use the value of the sambaSID attribute for
	# group of gidNumber=$userGidNumber
	$group_entry = read_group_entry_gid($userGidNumber);
	$userGroupSID = $group_entry->get_value('sambaSID');
	unless ($userGroupSID) {
	  print "$0: unknown group SID not set for unix group $userGidNumber\n";
	  print "check if your unix group is mapped to an NT group\n";
	  exit (7);
	}

	# as rid we use 2 * uid + 1000
	$userRid = 2 * $userUidNumber + 1000;
        # let's test if this SID already exist
	my $user_sid="$SID-$userRid";
        my $test_exist_sid=does_sid_exist($user_sid,$usersdn);
        if ($test_exist_sid->count == 1) {
                print "User SID already owned by\n";
                # there should not exist more than one entry, but ...
                foreach my $entry ($test_exist_sid->all_entries) {
                        my $dn= $entry->dn;
                        chomp($dn);
                        print "$dn\n";
                }
                exit(7);
        }
}

my $userHomeDirectory;
my ($userCN, $userSN);
my $tmp;
if (!defined($userHomeDirectory = $Options{'d'})) {
  $userHomeDirectory = $_userHomePrefix."/".$userName;
}
$_userLoginShell = $tmp if (defined($tmp = $Options{'s'}));
$_userGecos = $tmp if (defined($tmp = $Options{'c'}));
$_skeletonDir = $tmp if (defined($tmp = $Options{'k'}));
$userCN = ($Options{'c'} || $userName);
$userCN = $tmp if (defined($tmp = $Options{'N'}));
$userSN = $userName;
$userSN = $tmp if (defined($tmp = $Options{'S'}));


########################

my $ldap_master=connect_ldap_master();

# MACHINE ACCOUNT
if (defined($tmp = $Options{'w'})) {
   
  # add a trailing dollar if missing
  if ($userName =~ /[^\$]$/s) {
	$userName .= "\$";
  }

  #print "About to create machine $userName:\n";

  if (!add_posix_machine ($userName, $userUidNumber, $userGidNumber)) {
	die "$0: error while adding posix account\n";
  }

  if (!$with_smbpasswd) {
	# (jtournier)
	# Objectclass sambaSamAccount is now added directly by samba when joigning the domain (for samba3)
	#if (!add_samba_machine_mkntpwd($userName, $userUidNumber)) {
	#  die "$0: error while adding samba account\n";
	#}
  } else {
	if (!add_samba_machine($userName)) {
	  die "$0: error while adding samba account\n";
	}
	my $modify = $ldap_master->modify ( "$dn",
										changes => [
													replace => [sambaAcctFlags => '[W          ]']
												   ]
									  );
	$modify->code && warn "failed to modify entry: ", $modify->error ;
  }

  exit 0;
}

# USER ACCOUNT
# add posix account first

my $add = $ldap_master->add ("uid=$userName,$usersdn",
							 attr => [
									  'objectclass' => ['top','inetOrgPerson', 'posixAccount'],
									  'cn'   => "$userCN",
									  'sn'   => "$userSN",
									  'uid'   => "$userName",
									  'uidNumber'   => "$userUidNumber",
									  'gidNumber'   => "$userGidNumber",
									  'homeDirectory'   => "$userHomeDirectory",
									  'loginShell'   => "$_userLoginShell",
									  'gecos'   => "$_userGecos",
									  'description'   => "$_userGecos",
									  'userPassword'   => "{crypt}x"
									 ]
							);

$add->code && warn "failed to add entry: ", $add->error ;


#if ($createGroup) {
#    group_add($userName, $userGidNumber);
#}

group_add_user($userGidNumber, $userName);

my $grouplist;
# adds to supplementary groups
if (defined($grouplist = $Options{'G'})) {
  add_grouplist_user($grouplist, $userName);
}

# If user was created successfully then we should create his/her home dir
if (defined($tmp = $Options{'m'})) {
  unless ( $userName =~ /\$$/ ) {
    if ( !(-e $userHomeDirectory) ) {
	  system "mkdir $userHomeDirectory 2>/dev/null";
	  system "cp -a $_skeletonDir/.[a-z,A-Z]* $_skeletonDir/* $userHomeDirectory 2>/dev/null";
	  system "chown -R $userUidNumber:$userGidNumber $userHomeDirectory 2>/dev/null";
	  system "chmod 700 $userHomeDirectory 2>/dev/null"; 
    }
  }
}


# Add Samba user infos
if (defined($Options{'a'})) {
  if (!$with_smbpasswd) {

	my $winmagic = 2147483647;
	my $valpwdcanchange = 0;
	my $valpwdmustchange = $winmagic;
	my $valpwdlastset = 0;
	my $valacctflags = "[UX]";

	if (defined($tmp = $Options{'A'})) {
	  if ($tmp != 0) {
		$valpwdcanchange = "0";
	  } else {
		$valpwdcanchange = "$winmagic";
	  }
	}

	if (defined($tmp = $Options{'B'})) {
	  if ($tmp != 0) {
		$valpwdmustchange = "0";
		# To force a user to change his password:
		# . the attribut sambaPwdLastSet must be != 0
		# . the attribut sambaAcctFlags must not match the 'X' flag
		$valpwdlastset=$winmagic;
		$valacctflags = "[U]";
	  } else {
		$valpwdmustchange = "$winmagic";
	  }
	}

	if (defined($tmp = $Options{'H'})) {
	  $valacctflags = "$tmp";
	}


	my $modify = $ldap_master->modify ( "uid=$userName,$usersdn",
										changes => [
													add => [objectClass => 'sambaSamAccount'],
													add => [sambaPwdLastSet => "$valpwdlastset"],
													add => [sambaLogonTime => '0'],
													add => [sambaLogoffTime => '2147483647'],
													add => [sambaKickoffTime => '2147483647'],
													add => [sambaPwdCanChange => "$valpwdcanchange"],
													add => [sambaPwdMustChange => "$valpwdmustchange"],
													add => [displayName => "$_userGecos"],
													add => [sambaAcctFlags => "$valacctflags"],
													add => [sambaSID => "$SID-$userRid"]
												   ]
									  );
	
	$modify->code && die "failed to add entry: ", $modify->error ;

  } else {
	my $FILE="|smbpasswd -s -a $userName >/dev/null" ;
	open (FILE, $FILE) || die "$!\n";
	print FILE <<EOF;
x
x
EOF
    ;
	close FILE;
	if ($?) {
	  print "$0: error adding samba account\n";
	  exit (10);
	}
  }								# with_smbpasswd

  my @mods;
  my $valscriptpath;
  if (defined $_userScript) {
        $valscriptpath="$_userScript";
  } else {
        $valscriptpath = "$userName.cmd";
  }
  if (defined($tmp = $Options{'E'})) {
    $valscriptpath = "$tmp";
  }

  my $valsmbhome;
  if (defined $_userSmbHome) {
       $valsmbhome = "$_userSmbHome";
  }
  if (defined($tmp = $Options{'C'})) {
    $valsmbhome = "$tmp";
  }
  if (defined $valsmbhome) {
       push(@mods, 'sambaHomePath', $valsmbhome);
  }

  my $valhomedrive = "$_userHomeDrive";
  if (defined($tmp = $Options{'D'})) {
    $tmp = $tmp.":" unless ($tmp =~ /:/);
    $valhomedrive = "$tmp";
  }

  my $valprofilepath;
  if (defined $_userProfile) {
       $valprofilepath = "$_userProfile$userName";
  }

  if (defined($tmp = $Options{'F'})) {
    $valprofilepath = "$tmp";
  }
  if (defined $valprofilepath) {
       push(@mods, 'sambaProfilePath', $valprofilepath);
  }

  my $modify = $ldap_master->modify ( "uid=$userName,$usersdn",
									  changes => [
												  add => [sambaPrimaryGroupSID => "$userGroupSID"],
												  add => [sambaHomeDrive => "$valhomedrive"],
												  add => [sambaLogonScript => "$valscriptpath"],
												  add => [sambaLMPassword => 'XXX'],
												  add => [sambaNTPassword => 'XXX']
												 ]
									);
  $modify = $ldap_master->modify ( "uid=$userName,$usersdn",
                                                                       'replace' => { @mods }
                                                                       );


  $modify->code && die "failed to add entry: ", $modify->error ;

}
$ldap_master->unbind;			# take down session


if (defined($Options{'P'})) {
  exec "/usr/local/sbin/smbldap-passwd.pl $userName"
}

exit 0;

########################################

=head1 NAME

smbldap-useradd.pl - Create a new user or update default new 
  user information

=head1 SYNOPSIS

smbldap-useradd.pl [-c comment] [-d home_dir]
  [-g initial_group] [-G group[,...]]
  [-m [-k skeleton_dir]]
  [-s shell] [-u uid [ -o]] [-P]
  [-A canchange] [-B mustchange] [-C smbhome]
  [-D homedrive] [-E scriptpath] [-F profilepath]
  [-H acctflags] login

=head1 DESCRIPTION

Creating New Users
  The smbldap-useradd.pl command creates a new user account using
  the values specified on the  command  line  and  the default
  values from the system.
  The new user account will be entered into the system
  files as needed, the home directory  will  be  created, and 
  initial  files copied, depending on the command line options.

  You have to use smbldap-passwd to set the user password.
  For Samba users, rid is 2*uidNumber+1000, and primaryGroupID
  is 2*gidNumber+1001. Thus you may want to use
  smbldap-useradd.pl -a -g "Domain Admins" -u 500 Administrator
  to create a sambaDomainName administrator (admin rid is 0x1F4 = 500 and
											 grouprid is 0x200 = 512)

  Without any option, the account created will be an Unix (Posix)
  account. The following options may be used to add information:

-a     The user will have a Samba account (and Unix).

  -w     Creates an account for a Samba machine (Workstation), so that 
  it can join a sambaDomainName.

  -x     Creates rid and primaryGroupID in hex (for Samba 2.2.2 bug). Else
  decimal (2.2.2 patched from cvs or 2.2.x, x > 2)

  -c comment
  The new user's comment field (gecos).

       -d home_dir
              The new user will be created using home_dir as the value for the
              user's login directory.  The default is to append the login name
  to default_home and use that as the login directory name.

  -g initial_group
  The group name or number of the user's initial login group.  The
              group  name must exist.  A group number must refer to an already
              existing group.  The default group number is 1.

       -G group,[...]
              A list of supplementary groups which the user is also  a  member
              of.   Each  group is separated from the next by a comma, with no
              intervening whitespace.  The groups  are  subject  to  the  same
              restrictions as the group given with the -g option.  The default
              is for the user to belong only to the initial group.

       -m     The user's home directory will be created if it does not  exist.
  The  files  contained in skeleton_dir will be copied to the home
  directory if the -k option is used,  otherwise  the  files  con­
  tained  in /etc/skel will be used instead.  Any directories con­
  tained in skeleton_dir or  /etc/skel  will  be  created  in  the
  user's  home  directory as well.  The -k option is only valid in
              conjunction with the -m option.  The default is  to  not  create
              the directory and to not copy any files.

       -s shell
              The name of the user's login shell.  The  default  is  to  leave
  this  field blank, which causes the system to select the default
  login shell.

  -u uid The numerical value of  the  user's  ID.   This  value  must  be
              unique,  unless  the  -o option is used.  The value must be non-
              negative.  The default is to use the smallest ID  value  greater
              than 1000 and greater than every other user.

       -P     ends by invoking smbldap-passwd.pl

       -A     can change password ? 0 if no, 1 if yes

       -B     must change password ? 0 if no, 1 if yes

       -C     sambaHomePath (SMB home share, like '\\\\PDC-SRV\\homes')

       -D     sambaHomeDrive (letter associated with home share, like 'H:')

       -E     sambaLogonScript, relative to the [netlogon] share (DOS script to execute on login, like 'foo.bat')

       -F     sambaProfilePath (profile directory, like '\\\\PDC-SRV\\profiles\\foo')

       -H     sambaAcctFlags, spaces and trailing bracket are ignored (samba account control bits like '[NDHTUMWSLKI]')

       -N     canonical name (defaults to gecos or username, if gecos not set)

       -S     surname (defaults to username)


=head1 SEE ALSO

       useradd(1)

=cut

#'
