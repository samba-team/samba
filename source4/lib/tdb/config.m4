AC_CHECK_FUNCS(mmap pread pwrite)

if test x"$experimental" = x"yes"; then
	SMB_LIBRARY_ENABLE(libtdb,YES)
fi

