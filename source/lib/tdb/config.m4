
if test x"$experimental" = x"yes"; then
	SMB_LIBRARY_ENABLE(libtdb,YES)
fi

###############################
# start SMB_EXT_LIB_GDBM 
# check for gdbm.h and -lgdbm
AC_CHECK_HEADERS(gdbm.h)
AC_CHECK_LIB_EXT(gdbm, GDBM_LIBS, gdbm_open)
if test x"$ac_cv_header_gdbm_h" = x"yes" -a x"$ac_cv_lib_ext_gdbm_gdbm_open" = x"yes";then
	SMB_EXT_LIB_ENABLE(GDBM,YES)
fi
SMB_EXT_LIB(GDBM, $GDBM_LIBS)
# end SMB_EXT_LIB_GDBM
###############################

SMB_BINARY_ENABLE(tdbtest, NO)
if test x"$SMB_EXT_LIB_ENABLE_GDBM" = x"YES"; then
	SMB_BINARY_ENABLE(tdbtest, YES)
fi
