########################################################
# Compile with compression support

with_zlib_support=auto
ZLIB_LIBS=""
ZLIB_CFLAGS=""
ZLIB_CPPFLAGS=""
ZLIB_LDFLAGS=""

AC_CHECK_HEADERS(zlib.h)  
if test x"$ac_cv_header_zlib_h" != x"yes"; then
	with_zlib_support=no
fi

if test x"$with_zlib_support" != x"no"; then
  AC_CHECK_LIB_EXT(z, ZLIB_LIBS, inflate)

  if test x"$ac_cv_lib_ext_z_inflate" = x"yes"; then
    AC_DEFINE(HAVE_ZLIB,1,[Whether zlib is available])
    with_zlib_support=yes
    SMB_EXT_LIB_ENABLE(ZLIB,YES)
  else
    ZLIB_LIBS=""
    with_zlib_support=no
  fi
  LIBS=$ac_save_LIBS
fi
AC_MSG_CHECKING(whether ZLIB support is available)
AC_MSG_RESULT($with_zlib_support)

# for now enable this always but maybe all fields are empty
# TODO: move compression methods to seperate files each
SMB_EXT_LIB_ENABLE(ZLIB,YES)

SMB_EXT_LIB(ZLIB,[${ZLIB_LIBS}],[${ZLIB_CFLAGS}],[${ZLIB_CPPFLAGS}],[${ZLIB_LDFLAGS}])
