#################################################
# Check to see if we should use the included popt

INCLUDED_POPT=auto
AC_ARG_WITH(included-popt,
[  --with-included-popt    use bundled popt library, not from system],
[ 
case "$withval" in
	yes)
		INCLUDED_POPT=yes
		;;
        no)
        	INCLUDED_POPT=no
		;;
esac ],
)
if test x"$INCLUDED_POPT" != x"yes"; then
	AC_CHECK_HEADERS(popt.h)
	AC_CHECK_LIB_EXT(popt, TMP_LIBPOPT_LIBS, poptGetContext, [], [], INCLUDED_POPT=no)
	if test x"$ac_cv_header_popt_h" = x"no"; then
		INCLUDED_POPT=yes
		TMP_LIBPOPT_LIBS=""
	fi
fi

AC_MSG_CHECKING(whether to use included popt)
if test x"$INCLUDED_POPT" != x"no"; then
	TMP_LIBPOPT_OBJS="lib/popt/findme.o lib/popt/popt.o lib/popt/poptconfig.o \
				lib/popt/popthelp.o lib/popt/poptparse.o"
	CPPFLAGS="$CPPFLAGS -I$srcdir/lib/popt"
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi

#hack
LIBS="$LIBS ${TMP_LIBPOPT_LIBS}"

SMB_SUBSYSTEM(LIBPOPT,[],
		[${TMP_LIBPOPT_OBJS}],
		[])
