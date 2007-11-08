dnl test for getaddrinfo/getnameinfo
AC_CACHE_CHECK([for getaddrinfo],libreplace_cv_HAVE_GETADDRINFO,[
AC_TRY_LINK([
#include <sys/types.h>
#if STDC_HEADERS
#include <stdlib.h>
#include <stddef.h>
#endif
#include <sys/socket.h>
#include <netdb.h>],
[
struct sockaddr sa;
struct addrinfo *ai = NULL;
int ret = getaddrinfo(NULL, NULL, NULL, &ai);
if (ret != 0) {
	const char *es = gai_strerror(ret);
}
freeaddrinfo(ai);
ret = getnameinfo(&sa, sizeof(sa),
		NULL, 0,
		NULL, 0, 0);

],
libreplace_cv_HAVE_GETADDRINFO=yes,libreplace_cv_HAVE_GETADDRINFO=no)])
if test x"$libreplace_cv_HAVE_GETADDRINFO" = x"yes"; then
	AC_DEFINE(HAVE_GETADDRINFO,1,[Whether the system has getaddrinfo])
	AC_DEFINE(HAVE_GETNAMEINFO,1,[Whether the system has getnameinfo])
	AC_DEFINE(HAVE_FREEADDRINFO,1,[Whether the system has freeaddrinfo])
	AC_DEFINE(HAVE_GAI_STRERROR,1,[Whether the system has gai_strerror])
else
	LIBREPLACEOBJ="${LIBREPLACEOBJ} getaddrinfo.o"
fi
