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
$ldap_path $ldap_opts $ldapsearch $ldapsearchnobind
$ldapmodify $ldappasswd $ldapadd $ldapdelete $ldapmodrdn
$suffix $usersdn $computersdn
$groupsdn $scope $binddn $bindpasswd
$slaveDN $slavePw $masterDN $masterPw
$_userLoginShell $_userHomePrefix $_userGecos
$_defaultUserGid $_defaultComputerGid
$_skeletonDir $_userSmbHome
$_userProfile $_userHomeDrive
$_userScript $usersou $computersou $groupsou
);

use Exporter;
$VERSION = 1.00;
@ISA = qw(Exporter);

@EXPORT = qw(
$UID_START $GID_START $smbpasswd $slaveLDAP $masterLDAP
$slavePort $masterPort $ldapSSL $slaveURI $masterURI $with_smbpasswd $mk_ntpasswd
$ldap_path $ldap_opts $ldapsearch $ldapsearchnobind $ldapmodify $ldappasswd
$ldapadd $ldapdelete $ldapmodrdn $suffix $usersdn
$computersdn $groupsdn $scope $binddn $bindpasswd
$slaveDN $slavePw $masterDN $masterPw
$_userLoginShell $_userHomePrefix $_userGecos
$_defaultUserGid $_defaultComputerGid $_skeletonDir 
$_userSmbHome $_userProfile $_userHomeDrive $_userScript
$usersou $computersou $groupsou
);


##############################################################################
#
# General Configuration
#
##############################################################################

#
# UID and GID starting at...
#

$UID_START = 1000;
$GID_START = 1000;

# Put your own SID
# to obtain this number do: # net getlocalsid
our $SID='S-1-5-21-636805976-1992644568-3666589737';

##############################################################################
#
# LDAP Configuration
#
##############################################################################

# Notes: to use to dual ldap servers backend for Samba, you must patch
# Samba with the dual-head patch from IDEALX. If not using this patch
# just use the same server for slaveLDAP and masterLDAP.
#
# Slave LDAP : needed for read operations
#
# Ex: $slaveLDAP = "127.0.0.1";
$slaveLDAP = "127.0.0.1";

$slavePort = "389";

# 
# Master LDAP : needed for write operations
#
# Ex: $masterLDAP = "127.0.0.1";
$masterLDAP = "127.0.0.1";


#
# Master Port
# 389 636
# Ex: $masterPort = "
$masterPort = "389";

#
# Use SSL for LDAP
#
$ldapSSL = "0";

#
# LDAP Suffix
#
# Ex: $suffix = "dc=IDEALX,dc=ORG";
$suffix = "dc=IDEALX,dc=ORG";


# 
# Where are stored Users
#
# Ex: $usersdn = "ou=Users,$suffix"; for ou=Users,dc=IDEALX,dc=ORG
$usersou = q(_USERS_);

$usersdn = "ou=$usersou,$suffix";

# 
# Where are stored Computers
#
# Ex: $computersdn = "ou=Computers,$suffix"; for ou=Computers,dc=IDEALX,dc=ORG
$computersou = q(_COMPUTERS_);

$computersdn = "ou=$computersou,$suffix";

# 
# Where are stored Groups
# 
# Ex $groupsdn = "ou=Groups,$suffix"; for ou=Groups,dc=IDEALX,dc=ORG
$groupsou = q(_GROUPS_);

$groupsdn = "ou=$groupsou,$suffix";

#
# Default scope Used
#
$scope = "sub";

#
# Credential Configuration
#
# Bind DN used 
# Ex: $binddn = "cn=Manager,$suffix"; for cn=Manager,dc=IDEALX,dc=org
$binddn = "cn=Manager,$suffix";
#
# Bind DN passwd used
# Ex: $bindpasswd = 'secret'; for 'secret'
$bindpasswd = "secret";

#
# Notes: if using dual ldap patch, you can specify to different configuration
# By default, we will use the same DN (so it will work for standard Samba 
# release)
#
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
#
# Default Login Shell
#
# Ex: $_userLoginShell = q(/bin/bash);
$_userLoginShell = q(_LOGINSHELL_);

#
# Home directory prefix (without username)
#
#Ex: $_userHomePrefix = q(/home/);
$_userHomePrefix = q(_HOMEPREFIX_);

#
# Gecos
#
$_userGecos = q(System User);

#
# Default User (POSIX and Samba) GID
#
$_defaultUserGid = 100;

#
# Default Computer (Samba) GID
#
$_defaultComputerGid = 553;

#
# Skel dir
#
$_skeletonDir = q(/etc/skel);

##############################################################################
#
# SAMBA Configuration
#
##############################################################################

#
# The UNC path to home drives location without the username last extension
# (will be dynamically prepended)
# Ex: q(\\\\My-PDC-netbios-name\\homes) for \\My-PDC-netbios-name\homes
$_userSmbHome = q(\\\\_PDCNAME_\\homes);

#
# The UNC path to profiles locations without the username last extension
# (will be dynamically prepended)
# Ex: q(\\\\My-PDC-netbios-name\\profiles) for \\My-PDC-netbios-name\profiles
$_userProfile = q(\\\\_PDCNAME_\\profiles\\);

# 
# The default Home Drive Letter mapping
# (will be automatically mapped at logon time if home directory exist)
# Ex: q(U:) for U:
$_userHomeDrive = q(_HOMEDRIVE_);

#
# The default user netlogon script name
# if not used, will be automatically username.cmd
#
#$_userScript = q(startup.cmd); # make sure script file is edited under dos


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

if ( $ldapSSL eq "0" ) {
	$slaveURI = "ldap://$slaveLDAP:$slavePort";
	$masterURI = "ldap://$masterLDAP:$masterPort";
}
elsif ( $ldapSSL eq "1" ) {
	$slaveURI = "ldaps://$slaveLDAP:$slavePort";
	$masterURI = "ldaps://$masterLDAP:$masterPort";
}
else {
	die "ldapSSL option must be either 0 or 1.\n";
}
	

$ldap_path = "/usr/bin";
$ldap_opts = "-x";
$ldapsearch = "$ldap_path/ldapsearch $ldap_opts -H $slaveURI -D '$slaveDN' -w '$slavePw'";
$ldapsearchnobind = "$ldap_path/ldapsearch $ldap_opts -H $slaveURI";
$ldapmodify = "$ldap_path/ldapmodify $ldap_opts -H $masterURI -D '$masterDN' -w '$masterPw'";
$ldappasswd = "$ldap_path/ldappasswd $ldap_opts -H $masterURI -D '$masterDN' -w '$masterPw'";
$ldapadd = "$ldap_path/ldapadd $ldap_opts -H $masterURI -D '$masterDN' -w '$masterPw'";
$ldapdelete = "$ldap_path/ldapdelete $ldap_opts -H $masterURI -D '$masterDN' -w '$masterPw'";
$ldapmodrdn = "$ldap_path/ldapmodrdn $ldap_opts -H $masterURI -D '$masterDN' -w '$masterPw'";



1;

# - The End
