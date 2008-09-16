m4_include(../popt/libpopt.m4)

if test x"$POPT_OBJ" = "x"; then
	SMB_EXT_LIB(LIBPOPT, [${POPT_LIBS}])
else
	SMB_INCLUDE_MK(../popt/config.mk)
fi

