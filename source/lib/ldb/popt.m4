#################################################
# Check to see if we should use an external src dir

POPTDIR=""
AC_ARG_WITH(popt-src,
[  --with-popt-src    set location of popt source],
[
case "$withval" in
        yes|no)
		AC_MSG_ERROR([--with-popt-src called without argument])
                ;;
        *)
                POPTDIR="$withval"
                ;;
esac ],
)

if test x"$POPTDIR" = x; then
        AC_CHECK_HEADERS(popt.h)
        AC_CHECK_LIB(popt, poptGetContext)
else
	EXTRA_OBJ="$EXTRA_OBJ findme.o popt.o poptconfig.o popthelp.o poptparse.o"
	CFLAGS="$CFLAGS -I$POPTDIR"
fi

AC_CHECK_HEADERS([float.h alloca.h])
AC_CHECK_FUNCS(strerror)
AC_SUBST(POPTDIR)
