AC_CHECK_FUNCS(inet_ntoa,[],[LIBREPLACEOBJ="${LIBREPLACEOBJ} inet_ntoa.o"])

AC_CACHE_CHECK([for broken inet_ntoa],libreplace_cv_REPLACE_INET_NTOA,[
AC_TRY_RUN([
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
main() { struct in_addr ip; ip.s_addr = 0x12345678;
if (strcmp(inet_ntoa(ip),"18.52.86.120") &&
    strcmp(inet_ntoa(ip),"120.86.52.18")) { exit(0); }
exit(1);}],
           libreplace_cv_REPLACE_INET_NTOA=yes,libreplace_cv_REPLACE_INET_NTOA=no,libreplace_cv_REPLACE_INET_NTOA=cross)])
if test x"$libreplace_cv_REPLACE_INET_NTOA" = x"yes"; then
    AC_DEFINE(REPLACE_INET_NTOA,1,[Whether inet_ntoa should be replaced])
fi
