AC_CHECK_FUNCS(inet_pton,[],[LIBREPLACEOBJ="${LIBREPLACEOBJ} inet_pton.o"])
AC_CHECK_FUNCS(inet_ntop,[],[LIBREPLACEOBJ="${LIBREPLACEOBJ} inet_ntop.o"])
