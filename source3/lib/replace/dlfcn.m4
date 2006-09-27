dnl dummies provided by dlfcn.c if not available
save_LIBS="$LIBS"
LIBS=""

AC_SEARCH_LIBS(dlopen, dl)

AC_CHECK_HEADERS(dlfcn.h)

libreplace_cv_dlfcn=no
AC_CHECK_FUNCS([dlopen dlsym dlerror dlclose],[],[libreplace_cv_dlfcn=yes])

if test x"${libreplace_cv_dlfcn}" = x"yes";then
	LIBREPLACEOBJ="${LIBREPLACEOBJ} dlfcn.o"
fi

LIBDL="$LIBS"
AC_SUBST(LIBDL)
LIBS="$save_LIBS"
