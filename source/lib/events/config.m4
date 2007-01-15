# check for EPOLL and native Linux AIO interface
SMB_ENABLE(EVENTS_EPOLL, NO)
SMB_ENABLE(EVENTS_AIO, NO)
AC_CHECK_HEADERS(sys/epoll.h)
AC_CHECK_FUNCS(epoll_create)
if test x"$ac_cv_header_sys_epoll_h" = x"yes" -a x"$ac_cv_func_epoll_create" = x"yes";then
	SMB_ENABLE(EVENTS_EPOLL,YES)

	# check for native Linux AIO interface
	AC_CHECK_HEADERS(libaio.h)
	AC_CHECK_LIB_EXT(aio, AIO_LIBS, io_getevents)
	if test x"$ac_cv_header_libaio_h" = x"yes" -a x"$ac_cv_lib_ext_aio_io_getevents" = x"yes";then
		SMB_ENABLE(EVENTS_AIO,YES)
		AC_DEFINE(HAVE_LINUX_AIO, 1, [Whether Linux AIO is available])
	fi
fi
SMB_EXT_LIB(LIBAIO_LINUX, $AIO_LIBS)
