AC_CHECK_HEADERS(stdarg.h vararg.h)

dnl VA_COPY
AC_CACHE_CHECK([for va_copy],samba_cv_HAVE_VA_COPY,[
AC_TRY_LINK([#include <stdarg.h>
va_list ap1,ap2;], [va_copy(ap1,ap2);],
samba_cv_HAVE_VA_COPY=yes,samba_cv_HAVE_VA_COPY=no)])
if test x"$samba_cv_HAVE_VA_COPY" = x"yes"; then
    AC_DEFINE(HAVE_VA_COPY,1,[Whether va_copy() is available])
fi

if test x"$samba_cv_HAVE_VA_COPY" != x"yes"; then
AC_CACHE_CHECK([for __va_copy],samba_cv_HAVE___VA_COPY,[
AC_TRY_LINK([#include <stdarg.h>
va_list ap1,ap2;], [__va_copy(ap1,ap2);],
samba_cv_HAVE___VA_COPY=yes,samba_cv_HAVE___VA_COPY=no)])
if test x"$samba_cv_HAVE___VA_COPY" = x"yes"; then
    AC_DEFINE(HAVE___VA_COPY,1,[Whether __va_copy() is available])
fi
fi

AC_CHECK_TYPE(intptr_t, unsigned long long)
AC_CHECK_SIZEOF(size_t,cross)
AC_CHECK_SIZEOF(void *,cross)

if test $ac_cv_sizeof_size_t -lt $ac_cv_sizeof_void_p; then
	AC_WARN([size_t cannot represent the amount of used memory of a process])
	AC_WARN([please report this to <samba-technical@samba.org>])
	AC_WARN([sizeof(size_t) = $ac_cv_sizeof_size_t])
	AC_WARN([sizeof(void *) = $ac_cv_sizeof_void_p])
	AC_ERROR([sizeof(size_t) < sizeof(void *)])
fi
