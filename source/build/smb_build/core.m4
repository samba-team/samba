dnl SMB Build Core System
dnl -------------------------------------------------------
dnl  Copyright (C) Stefan (metze) Metzmacher 2004
dnl  Copyright (C) Jelmer Vernooij 2004
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

$PERL -I$srcdir/build/smb_build <<\_SMB_ACEOF
use strict;

my %INPUT;

use main;

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

smb_build_main(\%INPUT);

_SMB_ACEOF

])
