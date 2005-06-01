dnl $Id$

AC_DEFUN([KRB_PTHREADS], [
AC_MSG_CHECKING(if compiling threadsafe libraries)

if test "$PTHREADS_LIBS" = "" ; then
    PTHREADS_LIBS="-pthread"
fi

AC_ARG_ENABLE(pthread-support,
	AS_HELP_STRING([--enable-pthread-support],
			[if you want thread safe libraries]),
	[],[enable_pthread_support=maybe])
if test "$enable_pthread_support" = maybe; then
case "$host" in 
*-*-solaris2*)
	enable_pthread_support=yes
	if test "$GCC" = yes; then
		PTHREADS_CFLAGS=-pthreads
		PTHREADS_LIBS=-pthreads
	else
		PTHREADS_CFLAGS=-mt
		PTHREADS_LIBS=-mt
	fi
	;;
*-*-netbsd*)
	enable_pthread_support="if running netbsd 1.6T or newer"
	dnl heim_threads.h knows this
	PTHREADS_LIBS=""
	;;
*-*-freebsd5*)
	enable_pthread_support=yes
	;;
*-*-linux* | *-*-linux-gnu)
	case `uname -r` in
	2.*)
		enable_pthread_support=yes
		PTHREADS_CFLAGS=-pthread
		;;
	esac
	;;
*-*-aix*)
	if test "$GCC" = yes; then
		enable_pthread_support=yes
	else if expr "$CC" : ".*_r" > /dev/null ; then
		enable_pthread_support=yes
		PTHREADS_CFLAGS=""
		PTHREADS_LIBS=""
	else
		enable_pthread_support=no
	fi
	;;
mips-sgi-irix6.[[5-9]])  # maybe works for earlier versions too
	enable_pthread_support=yes
	PTHREADS_LIBS="-lpthread"
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
