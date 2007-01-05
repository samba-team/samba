AC_CHECK_HEADERS(sys/epoll.h)

# check for native Linux AIO interface
SMB_ENABLE(EVENTS_AIO, NO)
AC_CHECK_HEADERS(libaio.h)
AC_CHECK_LIB_EXT(aio, AIO_LIBS, io_getevents)
if test x"$ac_cv_header_libaio_h" = x"yes" -a x"$ac_cv_lib_ext_aio_io_getevents" = x"yes";then
	SMB_ENABLE(EVENTS_AIO,YES)
	AC_DEFINE(HAVE_LINUX_AIO, 1, [Whether Linux AIO is available])
fi
SMB_EXT_LIB(LIBAIO_LINUX, $AIO_LIBS)

# check for native Linux AIO interface
SMB_ENABLE(EVENTS_EPOLL, NO)
AC_CHECK_HEADERS(sys/epoll.h)
if test x"$ac_cv_header_sys_epoll_h" = x"yes";then
	SMB_ENABLE(EVENTS_EPOLL,YES)
fi

