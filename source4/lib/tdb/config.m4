
SMB_SUBSYSTEM_MK(LIBTDB,lib/tdb/config.mk)

if test x"$experimental" = x"yes"; then
	SMB_LIBRARY_ENABLE(libtdb,YES)
fi

SMB_LIBRARY_MK(libtdb,lib/tdb/config.mk)

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
SMB_BINARY_MK(tdbtest,lib/tdb/config.mk)

SMB_BINARY_MK(tdbtorture,lib/tdb/config.mk)

SMB_BINARY_MK(tdbdump,lib/tdb/config.mk)

# these are broken
#SMB_BINARY_MK(tdbtool,lib/tdb/config.mk)
#SMB_BINARY_MK(tdbbackup,lib/tdb/config.mk)
