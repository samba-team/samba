
SMB_SUBSYSTEM_MK(LIBTDB,lib/tdb/config.mk)

if test x"$experimental" = x"yes"; then
	SMB_LIBRARY_ENABLE(libtdb,YES)
fi

SMB_LIBRARY_MK(libtdb,lib/tdb/config.mk)

