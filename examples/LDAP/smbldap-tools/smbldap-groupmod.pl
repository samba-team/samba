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

# Purpose of smbldap-groupmod : group (posix) modification


use strict;
use FindBin;
use FindBin qw($RealBin);
use lib "$RealBin/";
use smbldap_tools;
use smbldap_conf;

#####################

use Getopt::Std;
my %Options;

my $ok = getopts('ag:n:m:or:s:t:x:?', \%Options);
if ( (!$ok) || (@ARGV < 1) || ($Options{'?'}) ) {
  print "Usage: $0 [-a] [-g gid [-o]] [-n name] [-m members(,)] [-x members (,)] [-r rid] [-s sid] [-t type] groupname\n";
  print "  -a   add automatic group mapping entry\n";
  print "  -g   new gid\n";
  print "  -o   gid is not unique\n";
  print "  -n   new group name\n";
  print "  -m   add members (comma delimited)\n";
  print "  -r   group-rid\n";
  print "  -s   group-sid\n";
  print "  -t   group-type\n"; 
  print "  -x   delete members (comma delimted)\n";
  print "  -?   show this help message\n";
  exit (1);
}

my $groupName = $ARGV[0];
my $group_entry;

if (! ($group_entry = read_group_entry($groupName))) {
  print "$0: group $groupName doesn't exist\n";
  exit (6);
}

my $newname = $Options{'n'};

my $nscd_status = system "/etc/init.d/nscd status >/dev/null 2>&1";

if ($nscd_status == 0) {
  system "/etc/init.d/nscd restart > /dev/null 2>&1";
}

my $gid = getgrnam($groupName);
unless (defined ($gid)) {
  print "$0: group $groupName not found!\n";
  exit(6);
}

my $tmp;
if (defined($tmp = $Options{'g'}) and $tmp =~ /\d+/) {
  if (!defined($Options{'o'})) {
	if (defined(getgrgid($tmp))) {
	  print "$0: gid $tmp exists\n";
	  exit (6);
	}
  }
  if (!($gid == $tmp)) {
	my $ldap_master=connect_ldap_master();
	my $modify = $ldap_master->modify ( "cn=$groupName,$groupsdn",
										changes => [
													replace => [gidNumber => $tmp]
												   ]
									  );
	$modify->code && die "failed to modify entry: ", $modify->error ;
	# take down session
	$ldap_master->unbind
  }
}


if (defined($newname)) {
  my $ldap_master=connect_ldap_master();
  my $modify = $ldap_master->moddn (
									"cn=$groupName,$groupsdn",
									newrdn => "cn=$newname",
									deleteoldrdn => "1",
									newsuperior => "$groupsdn"
								   );
  $modify->code && die "failed to modify entry: ", $modify->error ;
  # take down session
  $ldap_master->unbind
}

# Add members
if (defined($Options{'m'})) {
  my $members = $Options{'m'};
  my @members = split( /,/, $members );
  my $member;
  foreach $member ( @members ) {
	my $group_entry=read_group_entry($groupName);
	$groupsdn=$group_entry->dn;
	if (is_unix_user($member)) {
	  if (is_group_member($groupsdn,$member)) {
		print "User $member already in the group\n";
	  } else {
	  	print "adding user $member to group $groupName\n";
		my $ldap_master=connect_ldap_master();
		my $modify = $ldap_master->modify ($groupsdn,
											changes => [
														add => [memberUid => $member]
													   ]
										  );
		$modify->code && warn "failed to add entry: ", $modify->error ;
		# take down session
		$ldap_master->unbind
	  }
	} else {
	  print "User $member does not exist: create it first !\n";
	}
  }
}

# Delete members
if (defined($Options{'x'})) {
  my $members = $Options{'x'};
  my @members = split( /,/, $members );
  my $member;
  foreach $member ( @members ) {
        my $group_entry=read_group_entry($groupName);
        $groupsdn=$group_entry->dn;
	if (is_group_member("$groupsdn",$member)) {
	  print "deleting user $member from group $groupName\n";
	  my $ldap_master=connect_ldap_master();
	  my $modify = $ldap_master->modify ($groupsdn,
										  changes => [
													  delete => [memberUid => $member]
													 ]
										);
	  $modify->code && warn "failed to delete entry: ", $modify->error ;
	  # take down session
	  $ldap_master->unbind
	} else {
	  print "User $member is not in the group $groupName!\n";
	}
  }
}

my $group_sid;
if ($tmp= $Options{'s'}) {
  if ($tmp =~ /^S-(?:\d+-)+\d+$/) {
    $group_sid = $tmp;
  } else {
    print "$0: illegal group-rid $tmp\n";
    exit(7);
  }
} elsif ($Options{'r'} || $Options{'a'}) {
  my $group_rid;
  if ($tmp= $Options{'r'}) {
    if ($tmp =~ /^\d+$/) {
      $group_rid = $tmp;
    } else {
      print "$0: illegal group-rid $tmp\n";
      exit(7);
    }
  } else {
    # algorithmic mapping
    $group_rid = 2*$gid+1001;
  }
  $group_sid = $SID.'-'.$group_rid;
}

if ($group_sid) {
  my @adds;
  my @mods;
  push(@mods, 'sambaSID' => $group_sid);

  if ($tmp= $Options{'t'}) {
    my $group_type;
    if (defined($group_type = &group_type_by_name($tmp))) {
      push(@mods, 'sambaGroupType' => $group_type);
    } else {
      print "$0: unknown group type $tmp\n";
      exit(8);
    }
  } else {
    if (! defined($group_entry->get_value('sambaGroupType'))) {
      push(@mods, 'sambaGroupType' => group_type_by_name('domain'));
    }
  }

  my @oc = $group_entry->get_value('objectClass');
  unless (grep($_ =~ /^sambaGroupMapping$/i, @oc)) {
    push (@adds, 'objectClass' => 'sambaGroupMapping');
  }

  my $ldap_master=connect_ldap_master();
  my $modify = $ldap_master->modify ( "cn=$groupName,$groupsdn",
									  changes => [
												  'add' => [ @adds ],
												  'replace' => [ @mods ]
												 ]
									);
  $modify->code && warn "failed to delete entry: ", $modify->error ;
  # take down session
  $ldap_master->unbind
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
