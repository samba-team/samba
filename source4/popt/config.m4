#################################################
# Check to see if we should use the included popt 

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
    AC_CHECK_LIB(popt, poptGetContext,
	         INCLUDED_POPT=no, INCLUDED_POPT=yes)
fi

AC_MSG_CHECKING(whether to use included popt)
if test x"$INCLUDED_POPT" = x"yes"; then
    AC_MSG_RESULT(yes)
    BUILD_POPT='$(POPT_OBJS)'
    FLAGS1="-I$srcdir/popt"
else
    AC_MSG_RESULT(no)
    LIBS="$LIBS -lpopt"
fi
AC_SUBST(BUILD_POPT)
AC_SUBST(FLAGS1)
