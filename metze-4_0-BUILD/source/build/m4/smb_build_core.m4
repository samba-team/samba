dnl SMB Build Core System
dnl -------------------------------------------------------
dnl  Copyright (C) Stefan (metze) Metzmacher 2004
dnl  Released under the GNU GPL
dnl -------------------------------------------------------
dnl
dnl SMB_BUILD_CORE(
dnl		1: outputfile
dnl		)

dnl #######################################################
dnl ### And now the implementation			###
dnl #######################################################

dnl SMB_BUILD_CORE(
dnl		1: outputfile
dnl		)
AC_DEFUN([SMB_BUILD_CORE],
[

cat > config.smb_build.pl <<\_SMB_ACEOF
#!/usr/bin/perl -w
#

use strict;

my %modules;
my %subsystems;
my %libraries;
my %binaries;

_SMB_ACEOF

cat >> config.smb_build.pl <<\_SMB_ACEOF
###########################################################
### First we list all info from configure		###
###########################################################
#
#########################################
## Start Modules
$SMB_INFO_MODULES
## End Modules
#########################################
## Start Subsystems
$SMB_INFO_SUBSYSTEMS
## End Subsystems
#########################################
## Start Libraries
$SMB_INFO_LIBRARIES
## End Libraries
#########################################
## Start Binaries
$SMB_INFO_BINARIES
## End Binaries
#########################################

_SMB_ACEOF

$PERL config.smb_build.pl

rm -f config.smb_build.pl
])
