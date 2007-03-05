AC_ARG_ENABLE(socket-wrapper, 
[  --enable-socket-wrapper         Turn on socket wrapper library (default=no)])

DEFAULT_TEST_OPTIONS=
HAVE_SOCKET_WRAPPER=no

if eval "test x$developer = xyes"; then
	enable_socket_wrapper=yes
fi
    
if eval "test x$enable_socket_wrapper = xyes"; then
        AC_DEFINE(SOCKET_WRAPPER,1,[Use socket wrapper library])
	DEFAULT_TEST_OPTIONS=--socket-wrapper
	HAVE_SOCKET_WRAPPER=yes
fi

AC_SUBST(DEFAULT_TEST_OPTIONS)
AC_SUBST(HAVE_SOCKET_WRAPPER)
