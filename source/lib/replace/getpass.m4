AC_CACHE_CHECK([whether getpass should be replaced],samba_cv_REPLACE_GETPASS,[
SAVE_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="$CPPFLAGS -I$libreplacedir/"
AC_TRY_COMPILE([
#include "confdefs.h"
#define NO_CONFIG_H
#include "$libreplacedir/getpass.c"
],[],samba_cv_REPLACE_GETPASS=yes,samba_cv_REPLACE_GETPASS=no)
CPPFLAGS="$SAVE_CPPFLAGS"
])
if test x"$samba_cv_REPLACE_GETPASS" = x"yes"; then
	AC_DEFINE(REPLACE_GETPASS,1,[Whether getpass should be replaced])
	LIBREPLACEOBJ="${LIBREPLACEOBJ} getpass.o"
fi
