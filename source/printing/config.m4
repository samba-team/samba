############################################
# for cups support we need libcups, and a handful of header files

AC_ARG_ENABLE(cups,
[  --enable-cups           Turn on CUPS support (default=auto)])

if test x$enable_cups != xno; then
	AC_PATH_PROG(CUPS_CONFIG, cups-config)

        if test "x$CUPS_CONFIG" != x; then
                        AC_DEFINE(HAVE_CUPS,1,[Whether we have CUPS])
		CFLAGS="$CFLAGS `$CUPS_CONFIG --cflags`"
		LDFLAGS="$LDFLAGS `$CUPS_CONFIG --ldflags`"
		PRINTLIBS="$PRINTLIBS `$CUPS_CONFIG --libs`"
        fi
fi
