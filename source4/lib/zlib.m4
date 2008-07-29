
AC_CHECK_HEADERS(zlib.h)

# we require this new function...
AC_CHECK_LIB_EXT(z, ZLIB_LIBS, inflateReset2)

if test x"$ac_cv_header_zlib_h" = x"yes" -a \
	x"$ac_cv_lib_ext_z_inflateReset2" = x"yes"; then
	SMB_EXT_LIB(ZLIB, [${ZLIB_LIBS}])
else
	SMB_INCLUDE_MK(lib/zlib.mk)
fi
