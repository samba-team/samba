AC_CACHE_CHECK([for va_copy],samba_cv_HAVE_VA_COPY,[
AC_TRY_LINK([#include <stdarg.h>
va_list ap1,ap2;], [va_copy(ap1,ap2);],
samba_cv_HAVE_VA_COPY=yes,samba_cv_HAVE_VA_COPY=no)])
if test x"$samba_cv_HAVE_VA_COPY" = x"yes"; then
    AC_DEFINE(HAVE_VA_COPY,1,[Whether va_copy() is available])
fi

AC_CHECK_TYPES(intptr_t)
AC_CHECK_HEADERS(stdint.h stdarg.h unistd.h sys/types.h)
