# utils/net subsystem

#################################
# Start BINARY net
[BINARY::net]
INSTALLDIR = BINDIR
OBJ_FILES = \
		net.o \
		net_password.o \
		net_time.o \
		net_join.o \
		net_vampire.o \
		net_user.o
REQUIRED_SUBSYSTEMS = \
		CONFIG \
		LIBCMDLINE \
		LIBBASIC \
		LIBSMB \
		LIBNET
# End BINARY net
#################################
