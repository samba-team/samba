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

#################################
# First the infos from configure
cat > config.smb_build.pl <<\_SMB_ACEOF
#!/usr/bin/perl -w
#

use strict;

###########################################################
### First we list all info from configure		###
###########################################################
my %module;
my %subsystem;
my %library;
my %binary;
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

###########################################################
### Now do something:-)  TODO!!!			###
###########################################################
print "Here's the new build system!\n";

_SMB_ACEOF

$PERL config.smb_build.pl

rm -f config.smb_build.pl
])
