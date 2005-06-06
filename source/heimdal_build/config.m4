AC_CHECK_HEADERS(sys/file.h signal.h errno.h crypt.h curses.h sys/bittypes.h)
AC_CHECK_HEADERS(sys/stropts.h sys/timeb.h sys/times.h sys/uio.h sys/un.h)
AC_CHECK_HEADERS(sys/utsname.h termcap.h term.h timezone.h time.h ttyname.h)

AC_CHECK_FUNCS(setitimer uname umask unsetenv socket sendmsg putenv atexit)

