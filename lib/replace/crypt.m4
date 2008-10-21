###############################################
# test for where we get crypt() from
AC_CHECK_HEADERS(crypt.h)
AC_SEARCH_LIBS_EXT(crypt, [crypt],
  [test "$ac_cv_search_ext_crypt" = "none required" || CRYPT_LIBS="-lcrypt"
  AC_DEFINE(HAVE_CRYPT,1,[Whether the system has the crypt() function])],
  [ LIBREPLACEOBJ="${LIBREPLACEOBJ} crypt.o" ])
