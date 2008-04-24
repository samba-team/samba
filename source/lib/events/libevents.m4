dnl find the events sources. This is meant to work both for
dnl standalone builds, and builds of packages using libevents
eventsdir=""
eventspaths="$srcdir $srcdir/lib/events $srcdir/events $srcdir/../events"
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

EVENTS_OBJ="events.o events_select.o events_signal.o events_timed.o events_standard.o events_util.o"
AC_SUBST(LIBREPLACEOBJ)

AC_CHECK_HEADERS(sys/epoll.h)
AC_CHECK_FUNCS(epoll_create)

if test x"$ac_cv_header_sys_epoll_h" = x"yes" -a x"$ac_cv_func_epoll_create" = x"yes"; then
   EVENTS_OBJ="$EVENTS_OBJ events_epoll.o"
   AC_DEFINE(HAVE_EVENTS_EPOLL, 1, [Whether epoll available])
fi

AC_SUBST(EVENTS_OBJ)

