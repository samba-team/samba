dnl SMB Build Core System
dnl -------------------------------------------------------
dnl  Copyright (C) Stefan (metze) Metzmacher 2004
dnl  Released under the GNU GPL
dnl -------------------------------------------------------
dnl
dnl _SMB_BUILD_CORE(
dnl		1: outputfile
dnl		)

dnl #######################################################
dnl ### And now the implementation			###
dnl #######################################################

dnl _SMB_BUILD_CORE(
dnl		1: outputfile
dnl		)
AC_DEFUN([_SMB_BUILD_CORE],
[

echo "config.status: creating ./config.smb_build.pl"

cat > config.smb_build.pl <<\_SMB_ACEOF
#!$PERL -I$srcdir/build/smb_build
#

use strict;

my \$SMB_BUILD_CTX;

use main;

_SMB_ACEOF

echo "#line 8 \"build/smb_build/core.m4\"" >> config.smb_build.pl
cat >> config.smb_build.pl <<\_SMB_ACEOF
###########################################################
### First we list all info from configure		###
###########################################################
#
#########################################
## Start Build Env
$SMB_INFO_BUILD_ENV
## End Build Env
#########################################
#########################################
## Start Ext Libs
$SMB_INFO_EXT_LIBS
## End Ext Libs
#########################################
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

smb_build_main(\$SMB_BUILD_CTX);

_SMB_ACEOF

$PERL ./config.smb_build.pl || exit $?

])
