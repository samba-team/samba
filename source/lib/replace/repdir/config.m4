AC_CACHE_CHECK([for broken readdir],libreplace_READDIR_NEEDED,[
	AC_TRY_RUN([
#define test_readdir_os2_delete main
#error
#include "$libreplacedir/test/os2_delete.c"],
	[libreplace_READDIR_NEEDED=no],
	[libreplace_READDIR_NEEDED=yes],
	[libreplace_READDIR_NEEDED="assuming not"])
])

#
# try to replace with getdents() if needed
#
if test x"$libreplace_READDIR_NEEDED" = x"yes"; then
AC_CACHE_CHECK([for replacing readdir using getdents()],libreplace_READDIR_GETDENTS,[
	AC_TRY_RUN([
#include "confdefs.h"
#include "$libreplacedir/repdir/repdir.c"
#define test_readdir_os2_delete main
#include "$libreplacedir/test/os2_delete.c"],
	[libreplace_READDIR_GETDENTS=yes],
	[libreplace_READDIR_GETDENTS=no])
])
fi
if test x"$libreplace_READDIR_GETDENTS" = x"yes"; then
	AC_DEFINE(REPLACE_READDIR,1,[replace readdir])
	AC_DEFINE(REPLACE_READDIR_GETDENTS,1,[replace readdir using getdents()])
	LIBREPLACEOBJ="${LIBREPLACEOBJ} repdir/repdir.o"
	libreplace_READDIR_NEEDED=no
fi
