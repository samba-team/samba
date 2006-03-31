AC_CHECK_HEADERS([stdint.h inttypes.h])
AC_CHECK_TYPE(uint_t, unsigned int)
AC_CHECK_TYPE(int8_t, signed char)
AC_CHECK_TYPE(uint8_t, unsigned char)
AC_CHECK_TYPE(int16_t, short)
AC_CHECK_TYPE(uint16_t, unsigned short)
AC_CHECK_TYPE(int32_t, long)
AC_CHECK_TYPE(uint32_t, unsigned long)
AC_CHECK_TYPE(int64_t, long long)
AC_CHECK_TYPE(uint64_t, unsigned long long)
AC_CHECK_TYPE(u_int32_t, unsigned long)
AC_CHECK_TYPE(u_int16_t, unsigned short)
AC_CHECK_TYPE(u_int8_t, unsigned char)
AC_CHECK_TYPE(ssize_t, int)
AC_CHECK_TYPE(comparison_fn_t, 
[AC_DEFINE(HAVE_COMPARISON_FN_T, 1,[Whether or not we have comparison_fn_t])])

AC_CACHE_CHECK([for broken inet_ntoa],samba_cv_REPLACE_INET_NTOA,[
AC_TRY_RUN([
#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
main() { struct in_addr ip; ip.s_addr = 0x12345678;
if (strcmp(inet_ntoa(ip),"18.52.86.120") &&
    strcmp(inet_ntoa(ip),"120.86.52.18")) { exit(0); } 
exit(1);}],
           samba_cv_REPLACE_INET_NTOA=yes,samba_cv_REPLACE_INET_NTOA=no,samba_cv_REPLACE_INET_NTOA=cross)])
if test x"$samba_cv_REPLACE_INET_NTOA" = x"yes"; then
    AC_DEFINE(REPLACE_INET_NTOA,1,[Whether inet_ntoa should be replaced])
fi

dnl Provided by replace.c:
AC_TRY_COMPILE([
#include <sys/types.h>
#if STDC_HEADERS
#include <stdlib.h>
#include <stddef.h>
#endif
#include <sys/socket.h>], 
[socklen_t foo;],,
[AC_DEFINE(socklen_t, int,[Socket length type])])

AC_CHECK_HEADERS(sys/syslog.h syslog.h)
AC_CHECK_FUNCS(strtoull __strtoull strtouq strtoll __strtoll strtoq)
AC_CHECK_FUNCS(seteuid setresuid setegid setresgid chroot bzero strerror)
AC_CHECK_FUNCS(timegm setenv vsyslog setlinebuf mktime ftruncate chsize rename)
AC_CHECK_FUNCS(waitpid strnlen strlcpy strlcat innetgr initgroups memmove strdup)
AC_CHECK_FUNCS(pread pwrite strndup strcasestr)
AC_HAVE_DECL(setresuid, [#include <unistd.h>])
AC_HAVE_DECL(setresgid, [#include <unistd.h>])
AC_HAVE_DECL(errno, [#include <errno.h>])

AC_CACHE_CHECK([for secure mkstemp],samba_cv_HAVE_SECURE_MKSTEMP,[
AC_TRY_RUN([#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
main() { 
  struct stat st;
  char tpl[20]="/tmp/test.XXXXXX"; 
  int fd = mkstemp(tpl); 
  if (fd == -1) exit(1);
  unlink(tpl);
  if (fstat(fd, &st) != 0) exit(1);
  if ((st.st_mode & 0777) != 0600) exit(1);
  exit(0);
}],
samba_cv_HAVE_SECURE_MKSTEMP=yes,
samba_cv_HAVE_SECURE_MKSTEMP=no,
samba_cv_HAVE_SECURE_MKSTEMP=cross)])
if test x"$samba_cv_HAVE_SECURE_MKSTEMP" = x"yes"; then
    AC_DEFINE(HAVE_SECURE_MKSTEMP,1,[Whether mkstemp is secure])
fi

dnl Provided by snprintf.c:
AC_HAVE_DECL(asprintf, [#include <stdio.h>])
AC_HAVE_DECL(vasprintf, [#include <stdio.h>])
AC_HAVE_DECL(vsnprintf, [#include <stdio.h>])
AC_HAVE_DECL(snprintf, [#include <stdio.h>])
AC_CHECK_FUNCS(snprintf vsnprintf asprintf vasprintf)

AC_CACHE_CHECK([for C99 vsnprintf],samba_cv_HAVE_C99_VSNPRINTF,[
AC_TRY_RUN([
#include <sys/types.h>
#include <stdarg.h>
void foo(const char *format, ...) { 
       va_list ap;
       int len;
       char buf[20];
       long long l = 1234567890;
       l *= 100;

       va_start(ap, format);
       len = vsnprintf(buf, 0, format, ap);
       va_end(ap);
       if (len != 5) exit(1);

       va_start(ap, format);
       len = vsnprintf(0, 0, format, ap);
       va_end(ap);
       if (len != 5) exit(1);

       if (snprintf(buf, 3, "hello") != 5 || strcmp(buf, "he") != 0) exit(1);

       if (snprintf(buf, 20, "%lld", l) != 12 || strcmp(buf, "123456789000") != 0) exit(1);

       exit(0);
}
main() { foo("hello"); }
],
samba_cv_HAVE_C99_VSNPRINTF=yes,samba_cv_HAVE_C99_VSNPRINTF=no,samba_cv_HAVE_C99_VSNPRINTF=cross)])
if test x"$samba_cv_HAVE_C99_VSNPRINTF" = x"yes"; then
    AC_DEFINE(HAVE_C99_VSNPRINTF,1,[Whether there is a C99 compliant vsnprintf])
fi

dnl Provided by dlfcn.c:
AC_SEARCH_LIBS_EXT(dlopen, [dl], DL_LIBS)
SMB_EXT_LIB(DL,[${DL_LIBS}],[${DL_CFLAGS}],[${DL_CPPFLAGS}],[${DL_LDFLAGS}])
SAVE_LIBS="$LIBS"
LIBS="$LIBS $DL_LIBS"
AC_CHECK_HEADERS(dlfcn.h)
AC_CHECK_FUNCS(dlopen dlsym dlerror dlclose)
LIBS="$SAVE_LIBS"

AC_CHECK_FUNCS([syslog memset setnetgrent getnetgrent endnetgrent memcpy],,
			   [AC_MSG_ERROR([Required function not found])])

AC_CHECK_HEADERS(stdbool.h)

sinclude(lib/replace/readline.m4)
sinclude(lib/replace/getpass.m4)
