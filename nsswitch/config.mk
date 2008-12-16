[SUBSYSTEM::LIBWINBIND-CLIENT]
PRIVATE_DEPENDENCIES = SOCKET_WRAPPER

LIBWINBIND-CLIENT_OBJ_FILES = $(nsswitchsrcdir)/wb_common.o

#################################
# Start BINARY nsstest
[BINARY::nsstest]
INSTALLDIR = BINDIR
PRIVATE_DEPENDENCIES = \
		LIBSAMBA-UTIL \
		LIBREPLACE_EXT \
		LIBSAMBA-HOSTCONFIG
# End BINARY nsstest
#################################

nsstest_OBJ_FILES = $(nsswitchsrcdir)/nsstest.o

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
		$(nsswitchsrcdir)/wbinfo4.o
