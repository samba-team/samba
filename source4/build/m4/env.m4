dnl SMB Build Environment Checks
dnl -------------------------------------------------------
dnl  Copyright (C) Stefan (metze) Metzmacher 2004
dnl  Released under the GNU GPL
dnl -------------------------------------------------------
dnl

SMB_VERSION_STRING=`cat include/version.h | grep 'SAMBA_VERSION_OFFICIAL_STRING' | cut -d '"' -f2`
echo "SAMBA VERSION: ${SMB_VERSION_STRING}"

SAMBA_VERSION_SVN_REVISION=`cat include/version.h | grep 'SAMBA_VERSION_SVN_REVISION' | cut -d ' ' -f3-`
if test -n "${SAMBA_VERSION_SVN_REVISION}";then
	echo "BUILD REVISION: ${SAMBA_VERSION_SVN_REVISION}"
fi

SMB_INFO_BUILD_ENV=""

sinclude(build/m4/check_path.m4)
sinclude(build/m4/check_perl.m4)
sinclude(build/m4/check_cc.m4)
sinclude(build/m4/check_ld.m4)
sinclude(build/m4/check_shld.m4)
sinclude(build/m4/check_types.m4)
sinclude(build/m4/check_doc.m4)
