AC_CHECK_FUNCS(mmap pread pwrite)
AC_CHECK_HEADERS(getopt.h)

if test x"$experimental" = x"yes"; then
	SMB_LIBRARY_ENABLE(libtdb,YES)
fi

