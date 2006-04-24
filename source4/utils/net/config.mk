# utils/net subsystem

#################################
# Start BINARY net
[BINARY::net]
INSTALLDIR = BINDIR
PRIVATE_PROTO_HEADER = net_proto.h
OBJ_FILES = \
		net.o \
		net_password.o \
		net_time.o \
		net_join.o \
		net_vampire.o \
		net_user.o
PRIVATE_DEPENDENCIES = \
		LIBSAMBA-CONFIG \
		LIBSAMBA-UTIL \
		LIBSAMBA-NET \
		LIBPOPT \
		POPT_SAMBA \
		POPT_CREDENTIALS
# End BINARY net
#################################
