dnl SMB Build Environment Checks
dnl -------------------------------------------------------
dnl  Copyright (C) Stefan (metze) Metzmacher 2004
dnl  Released under the GNU GPL
dnl -------------------------------------------------------
dnl

AC_CANONICAL_HOST

AC_SUBST(srcdir)
export srcdir;

# we always set builddir to "." as that's nicer than
# having the absolute path of the current work directory
builddir=.
AC_SUBST(builddir)
export builddir;

SMB_VERSION_STRING=`cat ${srcdir}/include/version.h | grep 'SAMBA_VERSION_OFFICIAL_STRING' | cut -d '"' -f2`
echo "SAMBA VERSION: ${SMB_VERSION_STRING}"

SAMBA_VERSION_SVN_REVISION=`cat ${srcdir}/include/version.h | grep 'SAMBA_VERSION_SVN_REVISION' | cut -d ' ' -f3-`
if test -n "${SAMBA_VERSION_SVN_REVISION}";then
	echo "BUILD REVISION: ${SAMBA_VERSION_SVN_REVISION}"
fi

sinclude(build/m4/check_path.m4)
sinclude(build/m4/check_perl.m4)
sinclude(build/m4/check_cc.m4)
sinclude(build/m4/check_ld.m4)
sinclude(build/m4/check_types.m4)
sinclude(build/m4/check_doc.m4)
