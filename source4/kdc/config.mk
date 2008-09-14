# KDC server subsystem

#######################
# Start SUBSYSTEM KDC
[MODULE::KDC]
INIT_FUNCTION = server_service_kdc_init
SUBSYSTEM = smbd
PRIVATE_DEPENDENCIES = \
		HEIMDAL_KDC HDB_LDB
# End SUBSYSTEM KDC
#######################

KDC_OBJ_FILES = $(addprefix $(kdcsrcdir)/, kdc.o kpasswdd.o)

#######################
# Start SUBSYSTEM KDC
[SUBSYSTEM::HDB_LDB]
CFLAGS = -Iheimdal/kdc -Iheimdal/lib/hdb
PRIVATE_DEPENDENCIES = \
		LIBLDB auth_sam auth_sam_reply CREDENTIALS \
		HEIMDAL_HDB
# End SUBSYSTEM KDC
#######################

HDB_LDB_OBJ_FILES = $(addprefix $(kdcsrcdir)/, hdb-ldb.o pac-glue.o)
$(eval $(call proto_header_template,$(kdcsrcdir)/pac_glue.h,$(HDB_LDB_OBJ_FILES:.o=.c)))
