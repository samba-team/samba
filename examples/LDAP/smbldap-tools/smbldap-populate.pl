#!/usr/bin/perl -w

# Populate a LDAP base for Samba-LDAP usage
#

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

#  Purpose :
#       . Create an initial LDAP database suitable for Samba 2.2
#       . For lazy people, replace ldapadd (with only an ldif parameter)

use strict;
use FindBin;
use FindBin qw($RealBin);
use lib "$RealBin/";
use smbldap_tools;
use smbldap_conf;
use Getopt::Std;
use Net::LDAP::LDIF;

use vars qw(%oc);

# objectclass of the suffix
%oc = (
	   "ou" => "organizationalUnit",
	   "o" => "organization",
	   "dc" => "dcObject",
	  );


my %Options;

my $ok = getopts('a:b:?', \%Options);
if ( (!$ok) || ($Options{'?'}) ) {
  print "Usage: $0 [-ab?] [ldif]\n";
  print "  -a	administrator login name (default: Administrator)\n";
  print "  -b	guest login name (default: nobody)\n";
  print "  -?	show this help message\n";
  print "  ldif	file to add to ldap (default: suffix, Groups,";
  print " Users, Computers and builtin users )\n";
  exit (1);
}

my $_ldifName;
my $tmp_ldif_file="/tmp/$$.ldif";

if (@ARGV >= 1) {
  $_ldifName = $ARGV[0];
}

my $adminName = $Options{'a'};
if (!defined($adminName)) {
  $adminName = "Administrator";
}

my $guestName = $Options{'b'};
if (!defined($guestName)) {
  $guestName = "nobody";
}

if (!defined($_ldifName)) {
  my $attr;
  my $val;
  my $objcl;

  print "Using builtin directory structure\n";
  if ($suffix =~ m/([^=]+)=([^,]+)/) {
	$attr = $1;
	$val = $2;
	$objcl = $oc{$attr} if (exists $oc{$attr});
	if (!defined($objcl)) {
	  $objcl = "myhardcodedobjectclass";
	}
  } else {
	die "can't extract first attr and value from suffix $suffix";
  }
  #print "$attr=$val\n";
  my ($organisation,$ext) = ($suffix =~ m/dc=(.*),dc=(.*)$/);

  #my $FILE="|cat";
  my $FILE=$tmp_ldif_file;
  open (FILE, ">$FILE") || die "Can't open file $FILE: $!\n";

  print FILE <<EOF;
dn: $suffix
objectClass: $objcl
objectclass: organization
$attr: $val
o: $organisation

dn: $usersdn
objectClass: organizationalUnit
ou: $usersou

dn: $groupsdn
objectClass: organizationalUnit
ou: $groupsou

dn: $computersdn
objectClass: organizationalUnit
ou: $computersou

dn: uid=$adminName,$usersdn
cn: $adminName
sn: $adminName
objectClass: inetOrgPerson
objectClass: sambaSamAccount
objectClass: posixAccount
gidNumber: 512
uid: $adminName
uidNumber: 998
homeDirectory: $_userHomePrefix
sambaPwdLastSet: 0
sambaLogonTime: 0
sambaLogoffTime: 2147483647
sambaKickoffTime: 2147483647
sambaPwdCanChange: 0
sambaPwdMustChange: 2147483647
sambaHomePath: $_userSmbHome
sambaHomeDrive: $_userHomeDrive
sambaProfilePath: $_userProfile
sambaPrimaryGroupSID: $SID-512
sambaLMPassword: XXX
sambaNTPassword: XXX
sambaAcctFlags: [U          ]
sambaSID: $SID-2996
loginShell: /bin/false
gecos: Netbios Domain Administrator

dn: uid=$guestName,$usersdn
cn: $guestName
sn: $guestName
objectClass: inetOrgPerson
objectClass: sambaSamAccount
objectClass: posixAccount
gidNumber: 514
uid: $guestName
uidNumber: 999
homeDirectory: /dev/null
sambaPwdLastSet: 0
sambaLogonTime: 0
sambaLogoffTime: 2147483647
sambaKickoffTime: 2147483647
sambaPwdCanChange: 0
sambaPwdMustChange: 2147483647
sambaHomePath: $_userSmbHome
sambaHomeDrive: $_userHomeDrive
sambaProfilePath: $_userProfile
sambaPrimaryGroupSID: $SID-514
sambaLMPassword: NO PASSWORDXXXXXXXXXXXXXXXXXXXXX
sambaNTPassword: NO PASSWORDXXXXXXXXXXXXXXXXXXXXX
sambaAcctFlags: [NU         ]
sambaSID: $SID-2998
loginShell: /bin/false

dn: cn=Domain Admins,$groupsdn
objectClass: posixGroup
objectClass: sambaGroupMapping
gidNumber: 512
cn: Domain Admins
memberUid: $adminName
description: Netbios Domain Administrators
sambaSID: $SID-512
sambaGroupType: 2
displayName: Domain Admins

dn: cn=Domain Users,$groupsdn
objectClass: posixGroup
objectClass: sambaGroupMapping
gidNumber: 513
cn: Domain Users
description: Netbios Domain Users
sambaSID: $SID-513
sambaGroupType: 2
displayName: Domain Users

dn: cn=Domain Guests,$groupsdn
objectClass: posixGroup
objectClass: sambaGroupMapping
gidNumber: 514
cn: Domain Guests
description: Netbios Domain Guests Users
sambaSID: $SID-514
sambaGroupType: 2
displayName: Domain Guests

dn: cn=Administrators,$groupsdn
objectClass: posixGroup
objectClass: sambaGroupMapping
gidNumber: 544
cn: Administrators
description: Netbios Domain Members can fully administer the computer/sambaDomainName
sambaSID: $SID-544
sambaGroupType: 2
displayName: Administrators

dn: cn=Users,$groupsdn
objectClass: posixGroup
objectClass: sambaGroupMapping
gidNumber: 545
cn: Users
description: Netbios Domain Ordinary users
sambaSID: $SID-545
sambaGroupType: 2
displayName: users

dn: cn=Guests,$groupsdn
objectClass: posixGroup
objectClass: sambaGroupMapping
gidNumber: 546
cn: Guests
memberUid: $guestName
description: Netbios Domain Users granted guest access to the computer/sambaDomainName
sambaSID: $SID-546
sambaGroupType: 2
displayName: Guests

dn: cn=Power Users,$groupsdn
objectClass: posixGroup
objectClass: sambaGroupMapping
gidNumber: 547
cn: Power Users
description: Netbios Domain Members can share directories and printers
sambaSID: $SID-547
sambaGroupType: 2
displayName: Power Users

dn: cn=Account Operators,$groupsdn
objectClass: posixGroup
objectClass: sambaGroupMapping
gidNumber: 548
cn: Account Operators
description: Netbios Domain Users to manipulate users accounts
sambaSID: $SID-548
sambaGroupType: 2
displayName: Account Operators

dn: cn=Server Operators,$groupsdn
objectClass: posixGroup
objectClass: sambaGroupMapping
gidNumber: 549
cn: Server Operators
description: Netbios Domain Server Operators
sambaSID: $SID-549
sambaGroupType: 2
displayName: Server Operators

dn: cn=Print Operators,$groupsdn
objectClass: posixGroup
objectClass: sambaGroupMapping
gidNumber: 550
cn: Print Operators
description: Netbios Domain Print Operators
sambaSID: $SID-550
sambaGroupType: 2
displayName: Print Operators

dn: cn=Backup Operators,$groupsdn
objectClass: posixGroup
objectClass: sambaGroupMapping
gidNumber: 551
cn: Backup Operators
description: Netbios Domain Members can bypass file security to back up files
sambaSID: $SID-551
sambaGroupType: 2
displayName: Backup Operators

dn: cn=Replicator,$groupsdn
objectClass: posixGroup
objectClass: sambaGroupMapping
gidNumber: 552
cn: Replicator
description: Netbios Domain Supports file replication in a sambaDomainName
sambaSID: $SID-552
sambaGroupType: 2
displayName: Replicator

dn: cn=Domain Computers,$groupsdn
objectClass: posixGroup
objectClass: sambaGroupMapping
gidNumber: 553
cn: Domain Computers
description: Netbios Domain Computers accounts
sambaSID: $SID-553
sambaGroupType: 2
displayName: Domain Computers

EOF
  close FILE;
} else {
  $tmp_ldif_file=$_ldifName;
}

my $ldap_master=connect_ldap_master();
my $ldif = Net::LDAP::LDIF->new($tmp_ldif_file, "r", onerror => 'undef' );
while( not $ldif->eof() ) {
	my $entry = $ldif->read_entry();
	if ( $ldif->error() ) {
		print "Error msg: ",$ldif->error(),"\n";
		print "Error lines:\n",$ldif->error_lines(),"\n";
	} else {
		my $dn = $entry->dn;
		print "adding new entry: $dn\n";
		my $result=$ldap_master->add($entry);
		$result->code && warn "failed to add entry: ", $result->error ;
	}
}
$ldap_master->unbind;
system "rm -f $tmp_ldif_file";
exit(0);


########################################

=head1 NAME

smbldap-populate.pl - Populate your LDAP database

=head1 SYNOPSIS

  smbldap-populate.pl [ldif-file]

=head1 DESCRIPTION

       The smbldap-populate.pl command helps to populate an LDAP server
       by adding the necessary entries : base suffix (doesn't abort
       if already there), organizational units for users, groups and
       computers, builtin users : Administrator and guest, builtin
       groups (though posixAccount only, no SambaTNG support).

       -a name  Your local administrator login name (default: Administrator)
       -b name  Your local guest login name (default: nobody)

       If you give an extra parameter, it is assumed to be the ldif
       file to use instead of the builtin one. Options -a and -b
       will be ignored. 

=head1 FILES

       /usr/lib/perl5/site-perl/smbldap_conf.pm : Global parameters.

=head1 SEE ALSO

       smp(1)

=cut

#'



# - The End
