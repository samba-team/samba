# KDC server subsystem

#######################
# Start SUBSYSTEM KDC
[MODULE::KDC]
INIT_FUNCTION = server_service_kdc_init
SUBSYSTEM = service
PRIVATE_DEPENDENCIES = \
		HEIMDAL_KDC HDB_SAMBA4
# End SUBSYSTEM KDC
#######################

KDC_OBJ_FILES = $(addprefix $(kdcsrcdir)/, kdc.o kpasswdd.o)

#######################
# Start SUBSYSTEM KDC
[SUBSYSTEM::HDB_SAMBA4]
CFLAGS = -Iheimdal/kdc -Iheimdal/lib/hdb
PRIVATE_DEPENDENCIES = \
		LIBLDB auth_sam auth_sam_reply CREDENTIALS \
		HEIMDAL_HDB
# End SUBSYSTEM KDC
#######################

HDB_SAMBA4_OBJ_FILES = $(addprefix $(kdcsrcdir)/, hdb-samba4.o pac-glue.o)
$(eval $(call proto_header_template,$(kdcsrcdir)/pac_glue.h,$(HDB_SAMBA4_OBJ_FILES:.o=.c)))
