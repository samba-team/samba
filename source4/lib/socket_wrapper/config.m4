AC_ARG_ENABLE(socket-wrapper, 
[  --enable-socket-wrapper         Turn on socket wrapper library (default=no)],
    [if eval "test x$enable_socket_wrapper = xyes"; then
        AC_DEFINE(SOCKET_WRAPPER,1,[Use socket wrapper library])
    fi])
