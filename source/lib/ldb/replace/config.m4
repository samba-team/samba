AC_CHECK_HEADERS([stdint.h inttypes.h])
AC_CHECK_TYPE(uint8_t, unsigned char)
AC_CHECK_TYPE(int64_t, long long)
AC_CHECK_TYPE(uint64_t, unsigned long long)
AC_CHECK_TYPE(comparison_fn_t, 
[AC_DEFINE(HAVE_COMPARISON_FN_T, 1,[Whether or not we have comparison_fn_t])])

AC_CHECK_FUNCS(strerror timegm strnlen setenv)
AC_CHECK_FUNCS(strtoull __strtoull strtouq strtoll __strtoll strtoq)
AC_HAVE_DECL(errno, [#include <errno.h>])

AC_CHECK_HEADERS(strings.h)
