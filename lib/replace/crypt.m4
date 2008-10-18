###############################################
# test for where we get crypt() from
AC_SEARCH_LIBS(crypt, [crypt],
  [test "$ac_cv_search_crypt" = "none required" || CRYPT_LIBS="-lcrypt"
  AC_DEFINE(HAVE_CRYPT,1,[Whether the system has the crypt() function])],
  [ LIBREPLACEOBJ="${LIBREPLACEOBJ} crypt.o" ])
