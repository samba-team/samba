
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



AC_CHECK_HEADERS([				\
	crypt.h					\
	curses.h				\
	errno.h					\
	inttypes.h				\
	netdb.h					\
	signal.h				\
	sys/bitypes.h				\
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
	ttyname.h
])

AC_CHECK_FUNCS([				\
	atexit					\
	cgetent					\
	inet_ntop				\
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
	writev
])

love_FIND_FUNC(bswap16, [#ifdef HAVE_SYS_BSWAP_H
#include <sys/bswap.h>
#endif], 0)

love_FIND_FUNC(bswap32, [#ifdef HAVE_SYS_BSWAP_H
#include <sys/bswap.h>
#endif], 0)


AC_CHECK_DECL(h_errno, 
              [AC_DEFINE(HAVE_DECL_H_ERRNO,1,whether h_errno is declared)], [], [
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif])

# these are disabled unless heimdal is found below
SMB_MODULE_DEFAULT(KERBEROS_LIB, NOT)
SMB_BINARY_ENABLE(asn1_compile, NO)
SMB_BINARY_ENABLE(compile_et, NO)

# to enable kerberos, unpack a heimdal source tree in the heimdal directory
# of the samba source tree
if test -d heimdal; then
	AC_DEFINE(HAVE_KRB5,1,[Whether kerberos is available])
	CFLAGS="${CFLAGS} -Iheimdal_build -Iheimdal/lib/krb5 -Iheimdal/lib/gssapi -Iheimdal/lib/asn1 -Iheimdal/lib/com_err -Iheimdal/lib/hdb -Iheimdal/kdc"
	HAVE_KRB5=YES
	SMB_MODULE_DEFAULT(KERBEROS_LIB, STATIC)
	SMB_BINARY_ENABLE(asn1_compile, YES)
	SMB_BINARY_ENABLE(compile_et, YES)
fi
