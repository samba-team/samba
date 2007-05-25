m4_define([upcase],`echo $1 | tr abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ`)dnl

dnl love_FIND_FUNC(func, includes, arguments)
dnl kind of like AC_CHECK_FUNC, but with headerfiles
AC_DEFUN([love_FIND_FUNC], [

AC_MSG_CHECKING([for $1])
AC_CACHE_VAL(ac_cv_love_func_$1,
[
AC_LINK_IFELSE([AC_LANG_PROGRAM([[$2]],[[$1($3)]])],
[eval "ac_cv_love_func_$1=yes"],[eval "ac_cv_love_func_$1=no"])])

eval "ac_res=\$ac_cv_love_func_$1"

if false; then
	AC_CHECK_FUNCS($1)
fi
# $1
eval "ac_tr_func=HAVE_[]upcase($1)"

case "$ac_res" in
	yes)
	AC_DEFINE_UNQUOTED($ac_tr_func)
	AC_MSG_RESULT([yes])
	;;
	no)
	AC_MSG_RESULT([no])
	;;
esac


])

dnl Not all systems have err.h, so we provide a replacement. Heimdal
dnl unconditionally #includes <err.h>, so we need to create an err.h,
dnl but we can't just have a static one because we don't want to use
dnl it on systems that have a real err.h. If the system has a real
dnl err.h, we should use that (eg. on Darwin, the declarations get
dnl linker attributes added, so we can't guarantee that our local
dnl declarations will be correct). Phew!
AC_CHECK_HEADERS([err.h], [],
	[ cp heimdal/lib/roken/err.hin heimdal_build/err.h ])

AC_CHECK_HEADERS([				\
	crypt.h					\
	curses.h				\
	errno.h					\
	inttypes.h				\
	netdb.h					\
	signal.h				\
	sys/bswap.h				\
	sys/file.h				\
	sys/stropts.h				\
	sys/timeb.h				\
	sys/times.h				\
	sys/uio.h				\
	sys/un.h				\
	sys/utsname.h				\
	term.h					\
	termcap.h				\
	time.h					\
	timezone.h				\
	ttyname.h				\
	netinet/in.h				\
	netinet/in6.h				\
	netinet6/in6.h
])

AC_CHECK_FUNCS([				\
	atexit					\
	cgetent					\
	getprogname				\
	inet_aton				\
	gethostname				\
	getnameinfo				\
	iruserok				\
	putenv					\
	rcmd					\
	readv					\
	sendmsg					\
	setitimer				\
	socket					\
	strlwr					\
	strncasecmp				\
	strptime				\
	strsep					\
	strsep_copy				\
	strtok_r				\
	strupr					\
	swab					\
	umask					\
	uname					\
	unsetenv				\
	closefrom				\
	hstrerror				\
	err					\
	warn					\
	errx					\
	warnx					\
	flock					\
	getaddrinfo				\
	freeaddrinfo				\
	getipnodebyname				\
	getipnodebyaddr				\
	freehostent				\
	writev
])

love_FIND_FUNC(bswap16, [#ifdef HAVE_SYS_BSWAP_H
#include <sys/bswap.h>
#endif], 0)

love_FIND_FUNC(bswap32, [#ifdef HAVE_SYS_BSWAP_H
#include <sys/bswap.h>
#endif], 0)


dnl AC_HAVE_TYPE(TYPE,INCLUDES)
AC_DEFUN([AC_HAVE_TYPE], [
AC_REQUIRE([AC_HEADER_STDC])
cv=`echo "$1" | sed 'y%./+- %__p__%'`
AC_MSG_CHECKING(for $1)
AC_CACHE_VAL([ac_cv_type_$cv],
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
AC_INCLUDES_DEFAULT
$2]],
[[$1 foo;]])],
[eval "ac_cv_type_$cv=yes"],
[eval "ac_cv_type_$cv=no"]))dnl
ac_foo=`eval echo \\$ac_cv_type_$cv`
AC_MSG_RESULT($ac_foo)
if test "$ac_foo" = yes; then
  ac_tr_hdr=HAVE_`echo $1 | sed 'y%abcdefghijklmnopqrstuvwxyz./- %ABCDEFGHIJKLMNOPQRSTUVWXYZ____%'`
if false; then
	AC_CHECK_TYPES($1)
fi
  AC_DEFINE_UNQUOTED($ac_tr_hdr, 1, [Define if you have type `$1'])
fi
])

AC_HAVE_TYPE([sa_family_t],[#include <sys/socket.h>])
AC_HAVE_TYPE([struct sockaddr], [#include <sys/socket.h>])
AC_HAVE_TYPE([struct sockaddr_storage], [#include <sys/socket.h>])
AC_HAVE_TYPE([struct addrinfo], [#include <netdb.h>])
AC_HAVE_TYPE([struct ifaddrs], [#include <ifaddrs.h>])
AC_HAVE_TYPE([socklen_t],[#include <sys/socket.h>])


AC_DEFUN([AC_KRB_STRUCT_WINSIZE], [
AC_MSG_CHECKING(for struct winsize)
AC_CACHE_VAL(ac_cv_struct_winsize, [
ac_cv_struct_winsize=no
for i in sys/termios.h sys/ioctl.h; do
AC_EGREP_HEADER(
struct[[ 	]]*winsize,dnl
$i, ac_cv_struct_winsize=yes; break)dnl
done
])
if test "$ac_cv_struct_winsize" = "yes"; then
  AC_DEFINE(HAVE_STRUCT_WINSIZE, 1, [define if struct winsize is declared in sys/termios.h])
fi
AC_MSG_RESULT($ac_cv_struct_winsize)
AC_EGREP_HEADER(ws_xpixel, termios.h, 
	AC_DEFINE(HAVE_WS_XPIXEL, 1, [define if struct winsize has ws_xpixel]))
AC_EGREP_HEADER(ws_ypixel, termios.h, 
	AC_DEFINE(HAVE_WS_YPIXEL, 1, [define if struct winsize has ws_ypixel]))
])

AC_KRB_STRUCT_WINSIZE

AC_TYPE_SIGNAL
if test "$ac_cv_type_signal" = "void" ; then
	AC_DEFINE(VOID_RETSIGTYPE, 1, [Define if signal handlers return void.])
fi
AC_SUBST(VOID_RETSIGTYPE)


m4_include(heimdal/cf/check-var.m4)

rk_CHECK_VAR(h_errno, 
[#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif])

m4_include(heimdal/cf/find-func.m4)
m4_include(heimdal/cf/find-func-no-libs.m4)
m4_include(heimdal/cf/find-func-no-libs2.m4)
m4_include(heimdal/cf/resolv.m4)

smb_save_LIBS=$LIBS
RESOLV_LIBS=""
LIBS=""

dnl  This fills in the global LIBS...
rk_RESOLV

dnl AC_CHECK_LIB_EXT(resolv, RESOLV_LIBS, res_search)
	SMB_ENABLE(RESOLV,YES)

if test x"$LIBS" != "x"; then
	RESOLV_LIBS=$LIBS
fi

LIBS=$smb_save_LIBS

SMB_EXT_LIB(RESOLV,[${RESOLV_LIBS}],[${RESOLV_CFLAGS}],[${RESOLV_CPPFLAGS}],[${RESOLV_LDFLAGS}])


# these are disabled unless heimdal is found below
SMB_ENABLE(KERBEROS_LIB, NO)
SMB_ENABLE(asn1_compile, NO)
SMB_ENABLE(compile_et, NO)

AC_PROG_LEX
AC_PROG_YACC

# Portions of heimdal kerberos are unpacked into source/heimdal
# of the samba source tree.  

# if we ever get to using a host kerberos, we might add conditionals here
AC_DEFINE(HAVE_KRB5,1,[Whether kerberos is available])
HAVE_KRB5=YES
SMB_ENABLE(KERBEROS_LIB, YES)
SMB_ENABLE(asn1_compile, YES)
SMB_ENABLE(compile_et, YES)

# only add getaddrinfo and related functions if needed
SMB_ENABLE(HEIMDAL_ROKEN_ADDRINFO, NO)
if test t$ac_cv_func_getaddrinfo != tyes; then
	SMB_ENABLE(HEIMDAL_ROKEN_ADDRINFO, YES)
fi

# only add inet_aton if needed
SMB_ENABLE(HEIMDAL_ROKEN_INET_ATON, NO)
if test t$ac_cv_func_inet_aton != tyes; then
	SMB_ENABLE(HEIMDAL_ROKEN_INET_ATON, YES)
fi

# only add closefrom if needed
SMB_ENABLE(HEIMDAL_ROKEN_CLOSEFROM, NO)
if test t$ac_cv_func_closefrom != tyes; then
	SMB_ENABLE(HEIMDAL_ROKEN_CLOSEFROM, YES)
fi

# only add getprogname if needed
SMB_ENABLE(HEIMDAL_ROKEN_GETPROGNAME, NO)
SMB_ENABLE(HEIMDAL_ROKEN_GETPROGNAME_H, NO)
if test t$ac_cv_func_getprogname != tyes; then
	SMB_ENABLE(HEIMDAL_ROKEN_GETPROGNAME, YES)
	SMB_ENABLE(HEIMDAL_ROKEN_GETPROGNAME_H, YES)
fi

# only add gai_strerror if needed
SMB_ENABLE(HEIMDAL_ROKEN_GAI_STRERROR, NO)
AC_CHECK_FUNC(gai_strerror)

if test t$ac_cv_func_gai_strerror != tyes; then
    AC_CHECK_LIB_EXT(nsl, GAI_LIBS, gai_strerror)
    AC_CHECK_LIB_EXT(socket, GAI_LIBS, gai_strerror)
    AC_CHECK_LIB_EXT(xnet, GAI_LIBS, gai_strerror)

    dnl We can't just call AC_CHECK_FUNCS(gai_strerror) here, because the value
    dnl has been cached.
    if test x"$ac_cv_lib_ext_nsl_gai_strerror" = x"yes" ||
       test x"$ac_cv_lib_ext_socket_gai_strerror" = x"yes" ||
       test x"$ac_cv_lib_ext_xnet_gai_strerror" = x"yes"; then
        AC_DEFINE(HAVE_GAI_STRERROR,1,[Whether the system has gai_strerror()])
	SMB_ENABLE(GAI, YES)
    else
	SMB_ENABLE(HEIMDAL_ROKEN_GAI_STRERROR, YES)
    fi

else
    AC_DEFINE(HAVE_GAI_STRERROR,1,[Whether gai_strerror() is available])
fi

SMB_EXT_LIB(GAI,[${GAI_LIBS}],[${GAI_CFLAGS}],[${GAI_CPPFLAGS}],[${GAI_LDFLAGS}])
