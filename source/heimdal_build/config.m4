AC_CHECK_HEADERS(sys/file.h signal.h errno.h crypt.h curses.h sys/bitypes.h)
AC_CHECK_HEADERS(sys/stropts.h sys/timeb.h sys/times.h sys/uio.h sys/un.h inttypes.h)
AC_CHECK_HEADERS(sys/utsname.h termcap.h term.h timezone.h time.h ttyname.h netdb.h)

AC_CHECK_FUNCS(setitimer uname umask unsetenv socket sendmsg putenv atexit strsep)
AC_CHECK_FUNCS(strlwr strncasecmp strptime strsep_copy strtok_r strupr swab writev readv)
AC_CHECK_FUNCS(inet_ntop rcmd iruserok)

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
