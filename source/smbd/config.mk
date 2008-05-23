# server subsystem

[SUBSYSTEM::service]
PRIVATE_DEPENDENCIES = \
		MESSAGING samba-socket

service_OBJ_FILES = $(addprefix $(smbdsrcdir)/, \
		service.o \
		service_stream.o \
		service_task.o)

$(eval $(call proto_header_template,$(smbdsrcdir)/service_proto.h,$(service_OBJ_FILES:.o=.c)))

[SUBSYSTEM::PIDFILE]

PIDFILE_OBJ_FILES = $(smbdsrcdir)/pidfile.o

$(eval $(call proto_header_template,$(smbdsrcdir)/pidfile.h,$(PIDFILE_OBJ_FILES:.o=.c)))

#################################
# Start BINARY smbd
[BINARY::smbd]
INSTALLDIR = SBINDIR
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

smbd_OBJ_FILES = $(smbdsrcdir)/server.o

MANPAGES += $(smbdsrcdir)/smbd.8
# End BINARY smbd
#################################
