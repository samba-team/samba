[SUBSYSTEM::LIBWINBIND-CLIENT]
PRIVATE_DEPENDENCIES = SOCKET_WRAPPER

LIBWINBIND-CLIENT_OBJ_FILES = nsswitch/wb_common.o

#################################
# Start BINARY nsstest
[BINARY::nsstest]
INSTALLDIR = BINDIR
PRIVATE_DEPENDENCIES = \
		LIBSAMBA-UTIL \
		LIBREPLACE_EXT \
		LIBSAMBA-CONFIG
# End BINARY nsstest
#################################

nsstest_OBJ_FILES = nsswitch/nsstest.o

#################################
# Start BINARY wbinfo
[BINARY::wbinfo]
INSTALLDIR = BINDIR
PRIVATE_DEPENDENCIES = \
		LIBSAMBA-UTIL \
		LIBREPLACE_EXT \
		LIBCLI_AUTH \
		LIBPOPT \
		POPT_SAMBA \
		LIBWINBIND-CLIENT
# End BINARY nsstest
#################################

wbinfo_OBJ_FILES = \
		nsswitch/wbinfo.o
