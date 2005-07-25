AC_CACHE_CHECK([for broken readdir],samba_cv_HAVE_BROKEN_READDIR,[
	AC_TRY_RUN([#include "${srcdir-.}/build/tests/os2_delete.c"],
        	   samba_cv_HAVE_BROKEN_READDIR=no,samba_cv_HAVE_BROKEN_READDIR=yes)])

if test x"$samba_cv_HAVE_BROKEN_READDIR" = x"yes"; then
AC_CACHE_CHECK([for replacing readdir],samba_cv_REPLACE_READDIR,[
	AC_TRY_RUN([
#include "${srcdir-.}/lib/replace/repdir/repdir.c"
#include "${srcdir-.}/build/tests/os2_delete.c"],
       	   samba_cv_REPLACE_READDIR=yes,samba_cv_REPLACE_READDIR=no)])
fi

SMB_SUBSYSTEM_ENABLE(REPLACE_READDIR, NO)
if test x"$samba_cv_REPLACE_READDIR" = x"yes"; then
	AC_DEFINE(REPLACE_READDIR,1,[replace readdir])
	SMB_SUBSYSTEM_ENABLE(REPLACE_READDIR, YES)
fi
