dnl Check to see if we should use the included talloc

INCLUDED_TALLOC=auto
AC_ARG_WITH(included-talloc,
    [AC_HELP_STRING([--with-included-talloc], [use bundled talloc library, not from system])],
    [ INCLUDED_TALLOC=$withval ])

AC_SUBST(TALLOC_LIBS)
AC_SUBST(TALLOC_CFLAGS)

if test x"$INCLUDED_TALLOC" != x"yes" ; then
    AC_CHECK_HEADERS(talloc.h)
    AC_CHECK_LIB(talloc, talloc_init, [ TALLOC_LIBS="-ltalloc" ])
    if test x"$ac_cv_header_talloc_h" = x"no" -o x"$ac_cv_lib_talloc_talloc_init" = x"no" ; then
        INCLUDED_TALLOC=yes
        TALLOC_CFLAGS=""
    else
        INCLUDED_TALLOC=no
    fi
fi

AC_MSG_CHECKING(whether to use included talloc)
AC_MSG_RESULT($INCLUDED_TALLOC)
if test x"$INCLUDED_TALLOC" != x"no" ; then
    dnl find the talloc sources. This is meant to work both for 
    dnl talloc standalone builds, and builds of packages using talloc
    tallocdir=""
    tallocpaths=". lib/talloc talloc ../talloc ../lib/talloc"
    for d in $tallocpaths; do
    	if test -f "$srcdir/$d/talloc.c"; then
    		tallocdir="$d"
    		AC_SUBST(tallocdir)
    		break
    	fi
    done
    if test x"$tallocdir" = "x"; then
        AC_MSG_ERROR([cannot find talloc source in $tallocpaths])
    fi
    TALLOC_OBJ="talloc.o"
    AC_SUBST(TALLOC_OBJ)

    TALLOC_CFLAGS="-I$srcdir/$tallocdir"
    AC_SUBST(TALLOC_CFLAGS)

    TALLOC_LIBS=""
    AC_SUBST(TALLOC_LIBS)
fi

AC_CHECK_SIZEOF(size_t,cross)
AC_CHECK_SIZEOF(void *,cross)

if test $ac_cv_sizeof_size_t -lt $ac_cv_sizeof_void_p; then
	AC_WARN([size_t cannot represent the amount of used memory of a process])
	AC_WARN([please report this to <samba-technical@samba.org>])
	AC_WARN([sizeof(size_t) = $ac_cv_sizeof_size_t])
	AC_WARN([sizeof(void *) = $ac_cv_sizeof_void_p])
	AC_ERROR([sizeof(size_t) < sizeof(void *)])
fi

if test x"$VERSIONSCRIPT" != "x"; then
    EXPORTSFILE=talloc.exports
    AC_SUBST(EXPORTSFILE)
fi
