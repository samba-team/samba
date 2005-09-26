AC_CHECK_FUNCS(mmap pread pwrite getpagesize)
AC_CHECK_HEADERS(getopt.h sys/select.h sys/time.h)

AC_DEFINE([_GNU_SOURCE],[],[Pull in GNU extensions])

AC_HAVE_DECL(pread, [#include <unistd.h>])
AC_HAVE_DECL(pwrite, [#include <unistd.h>])

if test x"$experimental" = x"yes"; then
	SMB_LIBRARY_ENABLE(libtdb,YES)
fi

