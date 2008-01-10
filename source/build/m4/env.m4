dnl SMB Build Environment Checks
dnl -------------------------------------------------------
dnl  Copyright (C) Stefan (metze) Metzmacher 2004
dnl  Released under the GNU GPL
dnl -------------------------------------------------------
dnl

AC_SUBST(srcdir)
export srcdir;

# we always set builddir to "." as that's nicer than
# having the absolute path of the current work directory
builddir=.
AC_SUBST(builddir)
export builddir;

AC_SUBST(datarootdir)

SMB_VERSION_STRING=`cat ${srcdir}/version.h | grep 'SAMBA_VERSION_OFFICIAL_STRING' | cut -d '"' -f2`
echo "SAMBA VERSION: ${SMB_VERSION_STRING}"

SAMBA_VERSION_GIT_COMMIT_FULLREV=`cat ${srcdir}/version.h | grep 'SAMBA_VERSION_GIT_COMMIT_FULLREV' | cut -d ' ' -f3- | cut -d '"' -f2`
if test -n "${SAMBA_VERSION_GIT_COMMIT_FULLREV}";then
	echo "BUILD COMMIT REVISION: ${SAMBA_VERSION_GIT_COMMIT_FULLREV}"
fi
SAMBA_VERSION_GIT_COMMIT_DATE=`cat ${srcdir}/version.h | grep 'SAMBA_VERSION_GIT_COMMIT_DATE' | cut -d ' ' -f3-`
if test -n "${SAMBA_VERSION_GIT_COMMIT_DATE}";then
	echo "BUILD COMMIT DATE: ${SAMBA_VERSION_GIT_COMMIT_DATE}"
fi
SAMBA_VERSION_GIT_COMMIT_TIME=`cat ${srcdir}/version.h | grep 'SAMBA_VERSION_GIT_COMMIT_TIME' | cut -d ' ' -f3-`
if test -n "${SAMBA_VERSION_GIT_COMMIT_TIME}";then
	echo "BUILD COMMIT TIME: ${SAMBA_VERSION_GIT_COMMIT_TIME}"

	# just to keep the build-farm gui happy for now...
	echo "BUILD REVISION: ${SAMBA_VERSION_GIT_COMMIT_TIME}"
fi

m4_include(build/m4/check_path.m4)
m4_include(build/m4/check_perl.m4)
m4_include(build/m4/check_cc.m4)
m4_include(build/m4/check_ld.m4)
m4_include(build/m4/check_make.m4)
m4_include(build/m4/check_doc.m4)
