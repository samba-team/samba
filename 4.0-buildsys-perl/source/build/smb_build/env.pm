# SMB Build Environment Checks
# -------------------------------------------------------
#  Copyright (C) Stefan (metze) Metzmacher 2004
#  Released under the GNU GPL
# -------------------------------------------------------
#

$SMB_VERSION_STRING=`cat $srcdir/include/version.h | grep 'SAMBA_VERSION_OFFICIAL_STRING' | cut -d '"' -f2`;
print "SAMBA VERSION: $SMB_VERSION_STRING\n";

$SAMBA_VERSION_SVN_REVISION=`cat $srcdir/include/version.h | grep 'SAMBA_VERSION_SVN_REVISION' | cut -d ' ' -f3-`;
if ("$SAMBA_VERSION_SVN_REVISION" ne "") {
	print "BUILD REVISION: $SAMBA_VERSION_SVN_REVISION\n";
}

$SMB_INFO_BUILD_ENV="";

require "build/smb_build/check_path.pm";
require "build/smb_build/check_cc.pm";
require "build/smb_build/check_ld.pm";
require "build/smb_build/check_types.pm";
