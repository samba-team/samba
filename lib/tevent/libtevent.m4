dnl find the events sources. This is meant to work both for
dnl standalone builds, and builds of packages using libevents
if test x"$eventsdir" = "x"; then
	eventsdir=""
	eventspaths="$srcdir $srcdir/../samba4/source/lib/events $srcdir/lib/events $srcdir/events $srcdir/../events"
	for d in $eventspaths; do
		if test -f "$d/events.c"; then
			eventsdir="$d"
			AC_SUBST(eventsdir)
			break;
		fi
	done
	if test x"$eventsdir" = "x"; then
	   AC_MSG_ERROR([cannot find libevents source in $eventspaths])
	fi
fi

EVENTS_OBJ="events.o events_select.o events_signal.o events_timed.o events_standard.o events_debug.o events_util.o"
AC_LIBREPLACE_NETWORK_CHECKS

SMB_ENABLE(EVENTS_EPOLL, NO)
SMB_ENABLE(EVENTS_AIO, NO)
AC_CHECK_HEADERS(sys/epoll.h)
AC_CHECK_FUNCS(epoll_create)
if test x"$ac_cv_header_sys_epoll_h" = x"yes" -a x"$ac_cv_func_epoll_create" = x"yes"; then
   EVENTS_OBJ="$EVENTS_OBJ events_epoll.o"
   SMB_ENABLE(EVENTS_EPOLL,YES)
   AC_DEFINE(HAVE_EVENTS_EPOLL, 1, [Whether epoll available])

   # check for native Linux AIO interface
   AC_CHECK_HEADERS(libaio.h)
   AC_CHECK_LIB_EXT(aio, AIO_LIBS, io_getevents)
   if test x"$ac_cv_header_libaio_h" = x"yes" -a x"$ac_cv_lib_ext_aio_io_getevents" = x"yes";then
      EVENTS_OBJ="$EVENTS_OBJ events_aio.o"
      SMB_ENABLE(EVENTS_AIO,YES)
      AC_DEFINE(HAVE_LINUX_AIO, 1, [Whether Linux AIO is available])
   fi
fi

AC_SUBST(EVENTS_OBJ)
SMB_EXT_LIB(LIBAIO_LINUX, $AIO_LIBS)

EVENTS_CFLAGS="-I$eventsdir"
AC_SUBST(EVENTS_CFLAGS)

EVENTS_LIBS="$AIO_LIBS"
AC_SUBST(EVENTS_LIBS)


