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
#!/usr/bin/perl -W
#

use strict;

my \$SMB_BUILD_CTX;

_SMB_ACEOF

cat >> config.smb_build.pl < build/smb_build/config_mk.pl
cat >> config.smb_build.pl < build/smb_build/input.pl
cat >> config.smb_build.pl < build/smb_build/depend.pl
cat >> config.smb_build.pl < build/smb_build/output.pl
cat >> config.smb_build.pl < build/smb_build/makefile.pl
cat >> config.smb_build.pl < build/smb_build/smb_build_h.pl
cat >> config.smb_build.pl < build/smb_build/main.pl

cat >> config.smb_build.pl <<\_SMB_ACEOF
###########################################################
### First we list all info from configure		###
###########################################################
#
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

0;
_SMB_ACEOF

$PERL ./config.smb_build.pl || exit $?

])
