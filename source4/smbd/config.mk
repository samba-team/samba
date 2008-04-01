# server subsystem

################################################
# Start MODULE service_auth
[MODULE::service_auth]
INIT_FUNCTION = server_service_auth_init
SUBSYSTEM = service
PRIVATE_DEPENDENCIES = \
		auth
# End MODULE server_auth
################################################

[SUBSYSTEM::service]
PRIVATE_PROTO_HEADER = service_proto.h
OBJ_FILES = \
		service.o \
		service_stream.o \
		service_task.o
PRIVATE_DEPENDENCIES = \
		MESSAGING samba-socket

[SUBSYSTEM::PIDFILE]
OBJ_FILES = pidfile.o
PRIVATE_PROTO_HEADER = pidfile.h

#################################
# Start BINARY smbd
[BINARY::smbd]
INSTALLDIR = SBINDIR
OBJ_FILES = \
		server.o
PRIVATE_DEPENDENCIES = \
		process_model \
		service \
		LIBSAMBA-HOSTCONFIG \
		LIBSAMBA-UTIL \
		POPT_SAMBA \
		PIDFILE \
		LIBPOPT \
		gensec \
		registry \
		ntptr \
		ntvfs \
		share \
		CLUSTER

MANPAGES += smbd/smbd.8
# End BINARY smbd
#################################
