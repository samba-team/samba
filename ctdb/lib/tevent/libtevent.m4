dnl Check to see if we should use the included tevent

INCLUDED_TEVENT=auto
AC_ARG_WITH(included-tevent,
    [AC_HELP_STRING([--with-included-tevent], [use bundled tevent library, not from system])],
    [ INCLUDED_TEVENT=$withval ])

AC_SUBST(TEVENT_LIBS)
AC_SUBST(TEVENT_CFLAGS)

if test x"$INCLUDED_TEVENT" != x"yes" ; then
    AC_CHECK_HEADERS(tevent.h)
    AC_CHECK_LIB(tevent, tevent_context_init, [ TEVENT_LIBS="-ltevent" ])
    AC_CHECK_DECLS([TEVENT_TRACE_BEFORE_WAIT],,, [[#include <tevent.h>]])
    if test x"$ac_cv_header_tevent_h" = x"no" -o \
	x"$ac_cv_lib_tevent_tevent_context_init" = x"no" -o \
	x"$ac_cv_have_decl_TEVENT_TRACE_BEFORE_WAIT" = x"no" ; then
        INCLUDED_TEVENT=yes
        TEVENT_CFLAGS=""
    else
        INCLUDED_TEVENT=no
    fi
fi

AC_MSG_CHECKING(whether to use included tevent)
AC_MSG_RESULT($INCLUDED_TEVENT)
if test x"$INCLUDED_TEVENT" != x"no" ; then
    dnl find the tevent sources. This is meant to work both for
    dnl standalone builds, and builds of packages using libtevent
	teventdir=""
	teventpaths="$srcdir $srcdir/lib/tevent $srcdir/tevent $srcdir/../tevent"
	for d in $teventpaths; do
		if test -f "$d/tevent.c"; then
			teventdir="$d"
            AC_SUBST(teventdir)
			break
		fi
	done
	if test x"$teventdir" = "x"; then
	   AC_MSG_ERROR([cannot find tevent source in $teventpaths])
	fi
    TEVENT_OBJ="tevent.o tevent_debug.o tevent_util.o"
    TEVENT_OBJ="$TEVENT_OBJ tevent_fd.o tevent_timed.o tevent_immediate.o tevent_signal.o"
    TEVENT_OBJ="$TEVENT_OBJ tevent_req.o tevent_wakeup.o tevent_queue.o"
    TEVENT_OBJ="$TEVENT_OBJ tevent_standard.o tevent_select.o tevent_poll.o"
    AC_SUBST(TEVENT_OBJ)

    TEVENT_CFLAGS="-I$teventdir"
    AC_SUBST(TEVENT_CFLAGS)

    TEVENT_LIBS=""
    AC_SUBST(TEVENT_LIBS)

    AC_CHECK_HEADERS(sys/epoll.h)
    AC_CHECK_FUNCS(epoll_create)
    if test x"$ac_cv_header_sys_epoll_h" = x"yes" -a x"$ac_cv_func_epoll_create" = x"yes"; then
        TEVENT_OBJ="$TEVENT_OBJ tevent_epoll.o"
        AC_DEFINE(HAVE_EPOLL, 1, [Whether epoll available])
    fi
fi
