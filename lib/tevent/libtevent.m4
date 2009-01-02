dnl find the tevent sources. This is meant to work both for
dnl standalone builds, and builds of packages using libtevent
if test x"$teventdir" = "x"; then
	teventdir=""
	teventpaths="$srcdir $srcdir/../lib/tevent $srcdir/tevent $srcdir/../tevent"
	for d in $teventpaths; do
		if test -f "$d/tevent.c"; then
			teventdir="$d"
			AC_SUBST(teventdir)
			break;
		fi
	done
	if test x"$teventdir" = "x"; then
	   AC_MSG_ERROR([cannot find libtevent source in $teventpaths])
	fi
fi

TEVENT_OBJ="tevent.o tevent_select.o tevent_signal.o tevent_timed.o tevent_standard.o tevent_debug.o tevent_util.o"
AC_LIBREPLACE_NETWORK_CHECKS

SMB_ENABLE(TEVENT_EPOLL, NO)
SMB_ENABLE(TEVENT_AIO, NO)
AC_CHECK_HEADERS(sys/epoll.h)
AC_CHECK_FUNCS(epoll_create)
if test x"$ac_cv_header_sys_epoll_h" = x"yes" -a x"$ac_cv_func_epoll_create" = x"yes"; then
   TEVENT_OBJ="$TEVENT_OBJ tevent_epoll.o"
   SMB_ENABLE(TEVENT_EPOLL,YES)
   AC_DEFINE(HAVE_EPOLL, 1, [Whether epoll available])

   # check for native Linux AIO interface
   AC_CHECK_HEADERS(libaio.h)
   AC_CHECK_LIB_EXT(aio, AIO_LIBS, io_getevents)
   if test x"$ac_cv_header_libaio_h" = x"yes" -a x"$ac_cv_lib_ext_aio_io_getevents" = x"yes";then
      TEVENT_OBJ="$TEVENT_OBJ tevent_aio.o"
      SMB_ENABLE(TEVENT_AIO,YES)
      AC_DEFINE(HAVE_LINUX_AIO, 1, [Whether Linux AIO is available])
   fi
fi

AC_SUBST(TEVENT_OBJ)
SMB_EXT_LIB(LIBAIO_LINUX, $AIO_LIBS)

TEVENT_CFLAGS="-I$teventdir"
AC_SUBST(TEVENT_CFLAGS)

TEVENT_LIBS="$AIO_LIBS"
AC_SUBST(TEVENT_LIBS)


