[LIBRARY::LIBWINBIND-CLIENT]
VERSION = 0.0.1
SO_VERSION = 0
DESCRIPTION = Client library for communicating with winbind
OBJ_FILES = wb_common.o

#################################
# Start BINARY nsstest
[BINARY::nsstest]
INSTALLDIR = BINDIR
OBJ_FILES = \
		nsstest.o
PRIVATE_DEPENDENCIES = \
		LIBSAMBA-UTIL \
		LIBREPLACE_EXT
# End BINARY nsstest
#################################
