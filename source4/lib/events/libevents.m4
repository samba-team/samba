EVENTS_OBJ="lib/events/events.o lib/events/events_select.o lib/events/events_signal.o lib/events/events_timed.o lib/events/events_standard.o"

AC_CHECK_HEADERS(sys/epoll.h)
AC_CHECK_FUNCS(epoll_create)

if test x"$ac_cv_header_sys_epoll_h" = x"yes" -a x"$ac_cv_func_epoll_create" = x"yes"; then
   EVENTS_OBJ="$EVENTS_OBJ lib/events/events_epoll.o"
   AC_DEFINE(HAVE_EVENTS_EPOLL, 1, [Whether epoll available])
fi

AC_SUBST(EVENTS_OBJ)
