#!/usr/bin/perl
use strict;
package smbldap_conf;

# smbldap-tools.conf : Q & D configuration file for smbldap-tools

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
#       . be the configuration file for all smbldap-tools scripts

use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS
			$UID_START $GID_START $smbpasswd $slaveLDAP $masterLDAP
			$slavePort $masterPort $ldapSSL $slaveURI $masterURI $with_smbpasswd $mk_ntpasswd
			$ldap_path $ldap_opts $ldapmodify $suffix $usersdn $computersdn
			$groupsdn $scope $binddn $bindpasswd
			$slaveDN $slavePw $masterDN $masterPw
			$_userLoginShell $_userHomePrefix $_userGecos
			$_defaultUserGid $_defaultComputerGid
			$_skeletonDir $_userSmbHome
			$_userProfile $_userHomeDrive
			$_userScript $usersou $computersou $groupsou $SID $hash_encrypt $_defaultMaxPasswordAge
		   );

use Exporter;
$VERSION = 1.00;
@ISA = qw(Exporter);

@EXPORT = qw(
			 $UID_START $GID_START $smbpasswd $slaveLDAP $masterLDAP
			 $slavePort $masterPort $ldapSSL $slaveURI $masterURI $with_smbpasswd $mk_ntpasswd
			 $ldap_path $ldap_opts $ldapmodify $suffix $usersdn
			 $computersdn $groupsdn $scope $binddn $bindpasswd
			 $slaveDN $slavePw $masterDN $masterPw
			 $_userLoginShell $_userHomePrefix $_userGecos
			 $_defaultUserGid $_defaultComputerGid $_skeletonDir 
			 $_userSmbHome $_userProfile $_userHomeDrive $_userScript
			 $usersou $computersou $groupsou $SID $hash_encrypt $_defaultMaxPasswordAge
			);


##############################################################################
#
# General Configuration
#
##############################################################################

# UID and GID starting at...
$UID_START = 1000;
$GID_START = 1000;

# Put your own SID
# to obtain this number do: "net getlocalsid"
$SID='S-1-5-21-3516781642-1962875130-3438800523';

##############################################################################
#
# LDAP Configuration
#
##############################################################################

# Notes: to use to dual ldap servers backend for Samba, you must patch
# Samba with the dual-head patch from IDEALX. If not using this patch
# just use the same server for slaveLDAP and masterLDAP.
# Those two servers declarations can also be used when you have 
# . one master LDAP server where all writing operations must be done
# . one slave LDAP server where all reading operations must be done
#   (typically a replication directory)

# Ex: $slaveLDAP = "127.0.0.1";
$slaveLDAP = "127.0.0.1";
$slavePort = "389";

# Master LDAP : needed for write operations
# Ex: $masterLDAP = "127.0.0.1";
$masterLDAP = "127.0.0.1";
$masterPort = "389";

# Use SSL for LDAP
# If set to "1", this option will use start_tls for connection
# (you should also used the port 389)
$ldapSSL = "0";

# LDAP Suffix
# Ex: $suffix = "dc=IDEALX,dc=ORG";
$suffix = "dc=IDEALX,dc=COM";


# Where are stored Users
# Ex: $usersdn = "ou=Users,$suffix"; for ou=Users,dc=IDEALX,dc=ORG
$usersou = q(_USERS_);
$usersdn = "ou=$usersou,$suffix";

# Where are stored Computers
# Ex: $computersdn = "ou=Computers,$suffix"; for ou=Computers,dc=IDEALX,dc=ORG
$computersou = q(_COMPUTERS_);
$computersdn = "ou=$computersou,$suffix";

# Where are stored Groups
# Ex $groupsdn = "ou=Groups,$suffix"; for ou=Groups,dc=IDEALX,dc=ORG
$groupsou = q(_GROUPS_);
$groupsdn = "ou=$groupsou,$suffix";

# Default scope Used
$scope = "sub";

# Unix password encryption (CRYPT, MD5, SMD5, SSHA, SHA)
$hash_encrypt="SSHA";

############################
# Credential Configuration #
############################
# Bind DN used 
# Ex: $binddn = "cn=Manager,$suffix"; for cn=Manager,dc=IDEALX,dc=org
$binddn = "cn=Manager,$suffix";

# Bind DN passwd used
# Ex: $bindpasswd = 'secret'; for 'secret'
$bindpasswd = "secret";

# Notes: if using dual ldap patch, you can specify to different configuration
# By default, we will use the same DN (so it will work for standard Samba 
# release)
$slaveDN = $binddn;
$slavePw = $bindpasswd;
$masterDN = $binddn;
$masterPw = $bindpasswd;

##############################################################################
# 
# Unix Accounts Configuration
# 
##############################################################################

# Login defs
# Default Login Shell
# Ex: $_userLoginShell = q(/bin/bash);
$_userLoginShell = q(_LOGINSHELL_);

# Home directory prefix (without username)
# Ex: $_userHomePrefix = q(/home/);
$_userHomePrefix = q(_HOMEPREFIX_);

# Gecos
$_userGecos = q(System User);

# Default User (POSIX and Samba) GID
$_defaultUserGid = 513;

# Default Computer (Samba) GID
$_defaultComputerGid = 553;

# Skel dir
$_skeletonDir = q(/etc/skel);

# Default password validation time (time in days) Comment the next line if
# you don't want password to be enable for $_defaultMaxPasswordAge days (be
# careful to the sambaPwdMustChange attribute's value)
$_defaultMaxPasswordAge = 45;

##############################################################################
#
# SAMBA Configuration
#
##############################################################################

# The UNC path to home drives location without the username last extension
# (will be dynamically prepended)
# Ex: q(\\\\My-PDC-netbios-name\\homes) for \\My-PDC-netbios-name\homes
# Just comment this if you want to use the smb.conf 'logon home' directive
# and/or desabling roaming profiles
$_userSmbHome = q(\\\\_PDCNAME_\\homes);

# The UNC path to profiles locations without the username last extension
# (will be dynamically prepended)
# Ex: q(\\\\My-PDC-netbios-name\\profiles\\) for \\My-PDC-netbios-name\profiles
# Just comment this if you want to use the smb.conf 'logon path' directive
# and/or desabling roaming profiles
$_userProfile = q(\\\\_PDCNAME_\\profiles\\);

# The default Home Drive Letter mapping
# (will be automatically mapped at logon time if home directory exist)
# Ex: q(U:) for U:
$_userHomeDrive = q(_HOMEDRIVE_);

# The default user netlogon script name
# if not used, will be automatically username.cmd
# $_userScript = q(startup.cmd); # make sure script file is edited under dos


##############################################################################
#
# SMBLDAP-TOOLS Configuration (default are ok for a RedHat)
#
##############################################################################

# Allows not to use smbpasswd (if $with_smbpasswd == 0 in smbldap_conf.pm) but
# prefer mkntpwd... most of the time, it's a wise choice :-) 
$with_smbpasswd = 0;
$smbpasswd = "/usr/bin/smbpasswd";
$mk_ntpasswd = "/usr/local/sbin/mkntpwd";

# those next externals commands are kept fot the migration scripts and
# for the populate script: this will be updated as soon as possible
$slaveURI = "ldap://$slaveLDAP:$slavePort";
$masterURI = "ldap://$masterLDAP:$masterPort";

$ldap_path = "/usr/bin";

if ( $ldapSSL eq "0" ) {
	$ldap_opts = "-x";
} elsif ( $ldapSSL eq "1" ) {
	$ldap_opts = "-x -Z";
} else {
	die "ldapSSL option must be either 0 or 1.\n";
}

#$ldapsearch = "$ldap_path/ldapsearch $ldap_opts -H $slaveURI -D '$slaveDN' -w '$slavePw'";
#$ldapsearchnobind = "$ldap_path/ldapsearch $ldap_opts -H $slaveURI";
$ldapmodify = "$ldap_path/ldapmodify $ldap_opts -H $masterURI -D '$masterDN' -w '$masterPw'";
#$ldappasswd = "$ldap_path/ldappasswd $ldap_opts -H $masterURI -D '$masterDN' -w '$masterPw'";
#$ldapadd = "$ldap_path/ldapadd $ldap_opts -H $masterURI -D '$masterDN' -w '$masterPw'";
#$ldapdelete = "$ldap_path/ldapdelete $ldap_opts -H $masterURI -D '$masterDN' -w '$masterPw'";
#$ldapmodrdn = "$ldap_path/ldapmodrdn $ldap_opts -H $masterURI -D '$masterDN' -w '$masterPw'";



1;

# - The End
