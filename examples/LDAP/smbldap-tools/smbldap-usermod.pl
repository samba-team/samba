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

# Purpose of smbldap-usermod : user (posix,shadow,samba) modification

use strict;
use FindBin;
use FindBin qw($RealBin);
use lib "$RealBin/";
use smbldap_tools;
use smbldap_conf;

#####################

use Getopt::Std;
my %Options;
my $nscd_status;

my $ok = getopts('A:B:C:D:E:F:H:IJN:S:Pame:f:u:g:G:d:l:s:c:ok:?h', \%Options);
if ( (!$ok) || (@ARGV < 1) || ($Options{'?'}) || ($Options{'h'}) ) {
  print "Usage: $0 [-awmugdsckxABCDEFGHI?h] username\n";
  print "Available options are:\n";
  print "  -c    gecos\n";
  print "  -d    home directory\n";
  #print "  -m    move home directory\n";
  #print "  -f    inactive days\n";
  print "  -u    uid\n";
  print "  -o    uid can be non unique\n";
  print "  -g    gid\n";
  print "  -G    supplementary groups (comma separated)\n";
  print "  -l    login name\n";
  print "  -s    shell\n";
  print "  -N    canonical name\n";
  print "  -S    surname\n";
  print "  -P    ends by invoking smbldap-passwd.pl\n";
  print " For samba users:\n";
  print "  -a    add sambaSamAccount objectclass\n";
  print "  -e    expire date (\"YYYY-MM-DD HH:MM:SS\")\n";
  print "  -A    can change password ? 0 if no, 1 if yes\n";
  print "  -B    must change password ? 0 if no, 1 if yes\n";
  print "  -C    sambaHomePath (SMB home share, like '\\\\PDC-SRV\\homes')\n";
  print "  -D    sambaHomeDrive (letter associated with home share, like 'H:')\n";
  print "  -E    sambaLogonScript (DOS script to execute on login)\n";
  print "  -F    sambaProfilePath (profile directory, like '\\\\PDC-SRV\\profiles\\foo')\n";
  print "  -H    sambaAcctFlags (samba account control bits like '[NDHTUMWSLKI]')\n";
  print "  -I    disable an user. Can't be used with -H or -J\n";
  print "  -J    enable an user. Can't be used with -H or -I\n";
  print "  -?|-h show this help message\n";
  exit (1);
}

if ($< != 0) {
  print "You must be root to modify an user\n";
  exit (1);
}

# Read only first @ARGV
my $user = $ARGV[0];

# Read user data
my $user_entry = read_user_entry($user);
if (!defined($user_entry)) {
  print "$0: user $user doesn't exist\n";
  exit (1);
}

my $samba = 0;
if (grep ($_ =~ /^sambaSamAccount$/i, $user_entry->get_value('objectClass'))) {
  $samba = 1;
}

# get the dn of the user
my $dn= $user_entry->dn();

my $tmp;
my @mods;
if (defined($tmp = $Options{'a'})) {
	# Let's connect to the directory first
	my $ldap_master=connect_ldap_master();
        my $winmagic = 2147483647;
        my $valpwdcanchange = 0;
        my $valpwdmustchange = $winmagic;
        my $valpwdlastset = 0; 
        my $valacctflags = "[UX]";
	my $user_entry=read_user_entry($user);
	my $uidNumber = $user_entry->get_value('uidNumber');
	my $userRid = 2 * $uidNumber + 1000;
	# apply changes
	my $modify = $ldap_master->modify ( "$dn",
                                                                                changes => [
                                                                                                        add => [objectClass => 'sambaSamAccount'],
                                                                                                        add => [sambaPwdLastSet => "$valpwdlastset"],
                                                                                                        add => [sambaLogonTime => '0'],
                                                                                                        add => [sambaLogoffTime => '2147483647'],
                                                                                                        add => [sambaKickoffTime => '2147483647'],
                                                                                                        add => [sambaPwdCanChange => "$valpwdcanchange"],
                                                                                                        add => [sambaPwdMustChange => "$valpwdmustchange"],
                                                                                                        add => [displayName => "$_userGecos"],
                                                                                                        add => [sambaSID=> "$SID-$userRid"],
                                                                                                        add => [sambaAcctFlags => "$valacctflags"],
                                                                                                   ]
								  );
	$modify->code && warn "failed to modify entry: ", $modify->error ;
}

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
  push(@mods, 'uidNumber', $tmp);
  $_userUidNumber = $tmp;
  if ($samba) {
    # as rid we use 2 * uid + 1000
    my $_userRid = 2 * $_userUidNumber + 1000;
    if (defined($Options{'x'})) {
      $_userRid= sprint("%x", $_userRid);
    }
    push(@mods, 'sambaSID', $SID.'-'.$_userRid);
  }
  $changed_uid = 1;
}

my $changed_gid;
my $_userGidNumber;
my $_userGroupSID;
if (defined($tmp = $Options{'g'})) {
  $_userGidNumber = parse_group($tmp);
  if ($_userGidNumber < 0) {
	print "$0: group $tmp doesn't exist\n";
	exit (6);
  }
  push(@mods, 'gidNumber', $_userGidNumber);
  if ($samba) {
    # as grouprid we use the sambaSID attribute's value of the group
    my $group_entry = read_group_entry_gid($_userGidNumber);
    my $_userGroupSID = $group_entry->get_value('sambaSID');
    unless ($_userGroupSID) {
      print "$0: unknown group SID not set for unix group $_userGidNumber\n";
      exit (7);
    }
    push(@mods, 'sambaPrimaryGroupSid', $_userGroupSID);
  }
  $changed_gid = 1;
}

if (defined($tmp = $Options{'s'})) {
  push(@mods, 'loginShell' => $tmp);
}


if (defined($tmp = $Options{'c'})) {
  push(@mods, 'gecos' => $tmp,
	   'description' => $tmp);
  if ($samba == 1) {
    push(@mods, 'displayName' => $tmp);
  }
}

if (defined($tmp = $Options{'d'})) {
  push(@mods, 'homeDirectory' => $tmp);
}

if (defined($tmp = $Options{'N'})) { 
  push(@mods, 'cn' => $tmp);
}

if (defined($tmp = $Options{'S'})) { 
  push(@mods, 'sn' => $tmp);
}

if (defined($tmp = $Options{'G'})) {

  # remove user from old groups
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

$samba = is_samba_user($user);

if (defined($tmp = $Options{'e'})) {
  if ($samba == 1) {
	my $kickoffTime=`date --date='$tmp' +%s`;
	chomp($kickoffTime);
	push(@mods, 'sambakickoffTime' => $kickoffTime);
  } else {
  	print "User $user is not a samba user\n";
  }
}

my $_sambaPwdCanChange;
if (defined($tmp = $Options{'A'})) {
  if ($samba == 1) {
    $attr = "sambaPwdCanChange";
    if ($tmp != 0) {
      $_sambaPwdCanChange=0;
    } else {
      $_sambaPwdCanChange=$winmagic;
    }
    push(@mods, 'sambaPwdCanChange' => $_sambaPwdCanChange);
  } else {
  	print "User $user is not a samba user\n";
  }
}

my $_sambaPwdMustChange;
if (defined($tmp = $Options{'B'})) {
  if ($samba == 1) {
    if ($tmp != 0) {
      $_sambaPwdMustChange=0;
      # To force a user to change his password:
      # . the attribut sambaPwdLastSet must be != 0
      # . the attribut sambaAcctFlags must not match the 'X' flag
      my $_sambaAcctFlags;
      my $flags = $user_entry->get_value('sambaAcctFlags');
      if ( $flags =~ /X/ ) {
      	my $letters;
      	if ($flags =~ /(\w+)/) {
  		$letters = $1;
      	}
      	$letters =~ s/X//;
  	$_sambaAcctFlags="\[$letters\]";
      	push(@mods, 'sambaAcctFlags' => $_sambaAcctFlags);
      }
      my $_sambaPwdLastSet = $user_entry->get_value('sambaPwdLastSet');
      if ($_sambaPwdLastSet == 0) {
	push(@mods, 'sambaPwdLastSet' => $winmagic);
      }
    } else {
      $_sambaPwdMustChange=$winmagic;
    }
    push(@mods, 'sambaPwdMustChange' => $_sambaPwdMustChange);
  } else {
  	print "User $user is not a samba user\n";
  }
}

if (defined($tmp = $Options{'C'})) {
  if ($samba == 1) {
    #$tmp =~ s/\\/\\\\/g;
    push(@mods, 'sambaHomePath' => $tmp);
  } else {
  	print "User $user is not a samba user\n";
  }
}

my $_sambaHomeDrive;
if (defined($tmp = $Options{'D'})) {
  if ($samba == 1) {
    $tmp = $tmp.":" unless ($tmp =~ /:/);
    push(@mods, 'sambaHomeDrive' => $tmp);
  } else {
  	print "User $user is not a samba user\n";
  }
}

if (defined($tmp = $Options{'E'})) {
  if ($samba == 1) {
    #$tmp =~ s/\\/\\\\/g;
    push(@mods, 'sambaLogonScript' => $tmp);
  } else {
  	print "User $user is not a samba user\n";
  }
}

if (defined($tmp = $Options{'F'})) {
  if ($samba == 1) {
    #$tmp =~ s/\\/\\\\/g;
    push(@mods, 'sambaProfilePath' => $tmp);
  } else {
  	print "User $user is not a samba user\n";
  }
}

if ($samba == 1 and (defined $Options{'H'} or defined $Options{'I'} or defined $Options{'J'})) {
  my $_sambaAcctFlags;
  if (defined($tmp = $Options{'H'})) {
    #$tmp =~ s/\\/\\\\/g;
    $_sambaAcctFlags=$tmp;
  } else {
    # I or J
    my $flags;
    $flags = $user_entry->get_value('sambaAcctFlags');

    if (defined($tmp = $Options{'I'})) {
      if ( !($flags =~ /D/) ) {
		my $letters;
		if ($flags =~ /(\w+)/) {
		  $letters = $1;
		}
		$_sambaAcctFlags="\[D$letters\]";
      }
    } elsif (defined($tmp = $Options{'J'})) {
	  if ( $flags =~ /D/ ) {
		my $letters;
		if ($flags =~ /(\w+)/) {
		  $letters = $1;
		}
		$letters =~ s/D//;
		$_sambaAcctFlags="\[$letters\]";
	  }
	}
  }


  if ("$_sambaAcctFlags" ne '') {
    push(@mods, 'sambaAcctFlags' => $_sambaAcctFlags);
  }

} elsif (!$samba == 1 and (defined $Options{'H'} or defined $Options{'I'} or defined $Options{'J'})) {
  print "User $user is not a samba user\n";
}

# Let's connect to the directory first
my $ldap_master=connect_ldap_master();

# apply changes
my $modify = $ldap_master->modify ( "$dn",
									'replace' => { @mods }
								  );
$modify->code && warn "failed to modify entry: ", $modify->error ;

# take down session
$ldap_master->unbind;

$nscd_status = system "/etc/init.d/nscd status >/dev/null 2>&1";

if ($nscd_status == 0) {
  system "/etc/init.d/nscd restart > /dev/null 2>&1";
}

if (defined($Options{'P'})) {
  exec "/usr/local/sbin/smbldap-passwd.pl $user"
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
