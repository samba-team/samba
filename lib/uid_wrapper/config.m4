AC_ARG_ENABLE(uid-wrapper,
AS_HELP_STRING([--enable-uid-wrapper], [Turn on uid wrapper library (default=no)]))

HAVE_UID_WRAPPER=no

if eval "test x$developer = xyes -o x$selftest = xyes"; then
	enable_uid_wrapper=yes
fi

if eval "test x$enable_uid_wrapper = xyes"; then
        AC_DEFINE(UID_WRAPPER,1,[Use uid wrapper library])
	HAVE_UID_WRAPPER=yes

	# this is only used for samba3
	UID_WRAPPER_OBJS="../lib/uid_wrapper/uid_wrapper.o"
fi

AC_SUBST(HAVE_UID_WRAPPER)
AC_SUBST(UID_WRAPPER_OBJS)
