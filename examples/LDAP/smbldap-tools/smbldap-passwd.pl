#!/usr/bin/perl -w

# LDAP to unix password sync script for samba

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
#       . ldap-unix passwd sync for SAMBA>2.2.2 + LDAP
#       . may also replace /bin/passwd

use strict;
use FindBin;
use FindBin qw($RealBin);
use lib "$RealBin/";
use smbldap_tools;
use smbldap_conf;

my $user;
my $oldpass;
my $ret;

my $arg;

foreach $arg (@ARGV) {
  if ($< != 0) {
	die "Only root can specify parameters\n";
  } else {
	if ( ($arg eq '-?') || ($arg eq '--help') ) {
	  print "Usage: $0 [username]\n";
	  print "  -?, --help			show this help message\n";
	  exit (6);
	} elsif (substr($arg,0) ne '-') {
	  $user = $arg;
	}
	$oldpass = 1;
  }
}

if (!defined($user)) {
  $user=$ENV{"USER"};
}

# test existence of user in LDAP
my $dn_line;
if (!defined($dn_line = get_user_dn($user))) {
  print "$0: user $user doesn't exist\n";
  exit (10);
}

my $dn = get_dn_from_line($dn_line);

my $samba = is_samba_user($user);

print "Changing password for $user\n";

# non-root user
if (!defined($oldpass)) {
  # prompt for current password
  system "stty -echo";
  print "(current) UNIX password: ";
  chomp($oldpass=<STDIN>);
  print "\n";
  system "stty echo";

  if (!is_user_valid($user, $dn, $oldpass)) {
	print "Authentication failure\n";
	exit (10);
  }
}

# prompt for new password

my $pass;
my $pass2;

system "stty -echo";
print "New password : ";
chomp($pass=<STDIN>);
print "\n";
system "stty echo";

system "stty -echo";
print "Retype new password : ";
chomp($pass2=<STDIN>);
print "\n";
system "stty echo";

if ($pass ne $pass2) {
  print "New passwords don't match!\n";
  exit (10);
}

# First, connecting to the directory
my $ldap_master=connect_ldap_master();

# only modify smb passwords if smb user
if ($samba == 1) {
  if (!$with_smbpasswd) {
	# generate LanManager and NT clear text passwords
	if ($mk_ntpasswd eq '') {
	  print "Either set \$with_smbpasswd = 1 or specify \$mk_ntpasswd\n";
	  exit(1);
	}
	my $ntpwd = `$mk_ntpasswd '$pass'`;
	chomp(my $sambaLMPassword = substr($ntpwd, 0, index($ntpwd, ':')));
	chomp(my $sambaNTPassword = substr($ntpwd, index($ntpwd, ':')+1));
	# the sambaPwdLastSet must be updating
	my $date=time;
	my @mods;
	push(@mods, 'sambaLMPassword' => $sambaLMPassword);
	push(@mods, 'sambaNTPassword' => $sambaNTPassword);
	push(@mods, 'sambaPwdLastSet' => $date);
	if (defined $_defaultMaxPasswordAge) {
	  my $new_sambaPwdMustChange=$date+$_defaultMaxPasswordAge*24*60*60;
	  push(@mods, 'sambaPwdMustChange' => $new_sambaPwdMustChange);
	  push(@mods, 'sambaAcctFlags' => '[U]');
	}
	# Let's change nt/lm passwords
	my $modify = $ldap_master->modify ( "$dn",
										'replace' => { @mods }
									  );
	$modify->code && warn "failed to modify entry: ", $modify->error ;

  } else {
	if ($< != 0) {
	  my $FILE="|$smbpasswd -s >/dev/null";
	  open (FILE, $FILE) || die "$!\n";
	  print FILE <<EOF;
'$oldpass'
'$pass'
'$pass'
EOF
	  ;
	  close FILE;
	} else {
	  my $FILE="|$smbpasswd $user -s >/dev/null";
	  open (FILE, $FILE) || die "$!\n";
	  print FILE <<EOF;
'$pass'
'$pass'
EOF
	  ;
	  close FILE;
	}
  }
}

# change unix password
my $hash_password = `slappasswd -h {$hash_encrypt} -s '$pass'`;
chomp($hash_password);
my $modify = $ldap_master->modify ( "$dn",
									changes => [
												replace => [userPassword => "$hash_password"]
											   ]
								  );
$modify->code && warn "Unable to change password : ", $modify->error ;

# take down session
$ldap_master->unbind;

exit 0;


# - The End

=head1 NAME
       
smbldap-passwd.pl - change user password

=head1 SYNOPSIS
       
  smbldap-passwd.pl [name]

=head1 DESCRIPTION

smbldap-passwd.pl changes passwords for user accounts. A normal user
       may only change the password for their own account, the super user may
       change the password for any account.

   Password Changes
       The user is first prompted for their old password, if one is present.
       This password is then tested against the stored password by binding
       to the server. The user has only one chance to enter the correct pass-
       word. The super user is permitted to bypass this step so that forgot-
       ten passwords may be changed.

       The user is then prompted for a replacement password. As a general
       guideline, passwords should consist of 6 to 8 characters including
       one or more from each of following sets:

            Lower case alphabetics

            Upper case alphabetics

            Digits 0 thru 9

            Punctuation marks

       passwd will prompt again and compare the second entry against the first.
       Both entries are require to match in order for the password to be
       changed.

=head1 SEE ALSO

       passwd(1)

=cut

#'
