AC_CACHE_CHECK([for broken readdir],libreplace_READDIR_NEEDED,[
	AC_TRY_RUN([
#define test_readdir_os2_delete main
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
#include "$libreplacedir/repdir_getdents.c"
#define test_readdir_os2_delete main
#include "$libreplacedir/test/os2_delete.c"],
	[libreplace_READDIR_GETDENTS=yes],
	[libreplace_READDIR_GETDENTS=no])
])
fi
if test x"$libreplace_READDIR_GETDENTS" = x"yes"; then
	AC_DEFINE(REPLACE_READDIR,1,[replace readdir])
	AC_DEFINE(REPLACE_READDIR_GETDENTS,1,[replace readdir using getdents()])
	LIBREPLACEOBJ="${LIBREPLACEOBJ} repdir_getdents.o"
	libreplace_READDIR_NEEDED=no
fi

#
# try to replace with getdirentries() if needed
#
if test x"$libreplace_READDIR_NEEDED" = x"yes"; then
AC_CACHE_CHECK([for replacing readdir using getdirentries()],libreplace_READDIR_GETDIRENTRIES,[
	AC_TRY_RUN([
#include "confdefs.h"
#include "$libreplacedir/repdir_getdirentries.c"
#define test_readdir_os2_delete main
#include "$libreplacedir/test/os2_delete.c"],
	[libreplace_READDIR_GETDIRENTRIES=yes],
	[libreplace_READDIR_GETDIRENTRIES=no])
])
fi
if test x"$libreplace_READDIR_GETDIRENTRIES" = x"yes"; then
	AC_DEFINE(REPLACE_READDIR,1,[replace readdir])
	AC_DEFINE(REPLACE_READDIR_GETDIRENTRIES,1,[replace readdir using getdirentries()])
	LIBREPLACEOBJ="${LIBREPLACEOBJ} repdir_getdirentries.o"
	libreplace_READDIR_NEEDED=no
fi

if test x"$libreplace_READDIR_NEEDED" = x"yes"; then
	AC_MSG_WARN([the provides readdir() is broken])
fi
