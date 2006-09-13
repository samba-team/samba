AC_CACHE_CHECK([for broken readdir],samba_cv_HAVE_BROKEN_READDIR,[
	AC_TRY_RUN([
#define test_readdir_os2_delete main
#include "$libreplacedir/test/os2_delete.c"],
	[samba_cv_HAVE_BROKEN_READDIR=no],
	[samba_cv_HAVE_BROKEN_READDIR=yes],
	[samba_cv_HAVE_BROKEN_READDIR="assuming not"])
])

if test x"$samba_cv_HAVE_BROKEN_READDIR" = x"yes"; then
AC_CACHE_CHECK([for replacing readdir],samba_cv_REPLACE_READDIR,[
	AC_TRY_RUN([
#include "$libreplacedir/repdir/repdir.c"
#define test_readdir_os2_delete main
#include "$libreplacedir/test/os2_delete.c"],
	[samba_cv_REPLACE_READDIR=yes],
	[samba_cv_REPLACE_READDIR=no])
])
fi

SMB_ENABLE(REPLACE_READDIR, NO)
if test x"$samba_cv_REPLACE_READDIR" = x"yes"; then
	AC_DEFINE(REPLACE_READDIR,1,[replace readdir])
	SMB_ENABLE(REPLACE_READDIR, YES)
fi
