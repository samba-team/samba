dnl $Id$

AC_DEFUN([KRB_PTHREADS], [
AC_MSG_CHECKING(if compiling threadsafe libraries)

if test "$PTHREADS_LIBS" = "" ; then
    PTHREADS_LIBS="-pthread"
fi

AC_ARG_ENABLE(pthread-support,
	AC_HELP_STRING([--enable-pthread-support],
			[if you want thread safe libraries]),
	[],[enable_pthread_support=maybe])
if test "$enable_pthread_support" = maybe; then
case "$host" in 
*-*-solaris2*)
	enable_pthread_support=yes
	;;
*-*-netbsd*)
	enable_pthread_support="if running netbsd 1.6T or newer"
	dnl heim_threads.h knows this
	PTHREADS_LIBS=""
	;;
*-*-freebsd5*)
	enable_pthread_support=yes
	;;
*-*-linux2[4-9]*)
	enable_pthread_support=yes
	;;
*-*-aix*)
	enable_pthread_support=yes
	;;
*)
	enable_pthread_support=no
	;;
esac
fi
if test "$enable_pthread_support" != no; then
    AC_DEFINE(ENABLE_PTHREAD_SUPPORT, 1,
	[Define if you want have a thread safe libraries])
    dnl This sucks, but libtool doesn't save the depenecy on -pthread
    dnl for libraries.
    LIBS="$PTHREADS_LIBS $LIBS"
else
  PTHREADS_CFLAGS=""
  PTHREADS_LIBS=""
fi

AC_SUBST(PTHREADS_CFLAGS)
AC_SUBST(PTHREADS_LIBS)

AC_MSG_RESULT($enable_pthread_support)
])
