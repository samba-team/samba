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
PRIVATE_DEPENDENCIES = \
		MESSAGING samba-socket

service_OBJ_FILES = $(addprefix smbd/, \
		service.o \
		service_stream.o \
		service_task.o)

[SUBSYSTEM::PIDFILE]
PRIVATE_PROTO_HEADER = pidfile.h

PIDFILE_OBJ_FILES = smbd/pidfile.o

#################################
# Start BINARY smbd
[BINARY::smbd]
INSTALLDIR = SBINDIR
PRIVATE_DEPENDENCIES = \
		process_model \
		service \
		LIBSAMBA-CONFIG \
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

smbd_OBJ_FILES = smbd/server.o

MANPAGES += smbd/smbd.8
# End BINARY smbd
#################################
