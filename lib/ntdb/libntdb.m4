dnl find the ntdb sources. This is meant to work both for
dnl ntdb standalone builds, and builds of packages using ntdb
ntdbdir=""
ntdbpaths=". lib/ntdb ntdb ../ntdb ../lib/ntdb"
for d in $ntdbpaths; do
	if test -f "$srcdir/$d/ntdb.c"; then
		ntdbdir="$d"
		AC_SUBST(ntdbdir)
		break;
	fi
done
if test x"$ntdbdir" = "x"; then
   AC_MSG_ERROR([cannot find ntdb source in $ntdbpaths])
fi
NTDB_OBJ="check.o free.o hash.o io.o lock.o ntdb.o open.o pyntdb.o summary.o transaction.o traverse.o"
AC_SUBST(NTDB_OBJ)
AC_SUBST(LIBREPLACEOBJ)
AC_SUBST(CCAN_OBJ)

NTDB_LIBS=""
AC_SUBST(NTDB_LIBS)

NTDB_DEPS=""
if test x$libreplace_cv_HAVE_FDATASYNC_IN_LIBRT = xyes ; then
	NTDB_DEPS="$NTDB_DEPS -lrt"
fi
AC_SUBST(NTDB_DEPS)

NTDB_CFLAGS="-I$ntdbdir"
AC_SUBST(NTDB_CFLAGS)

AC_CHECK_FUNCS(mmap pread pwrite getpagesize utime)
AC_CHECK_HEADERS(getopt.h sys/select.h sys/time.h)

AC_HAVE_DECL(pread, [#include <unistd.h>])
AC_HAVE_DECL(pwrite, [#include <unistd.h>])

if test x"$VERSIONSCRIPT" != "x"; then
    EXPORTSFILE=ntdb.exports
    AC_SUBST(EXPORTSFILE)
fi
