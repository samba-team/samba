# KDC server subsystem

#######################
# Start SUBSYSTEM KDC
[MODULE::KDC]
INIT_FUNCTION = server_service_kdc_init
SUBSYSTEM = smbd
PRIVATE_DEPENDENCIES = \
		LIBLDB HEIMDAL HEIMDAL_KDC HEIMDAL_HDB SAMDB
# End SUBSYSTEM KDC
#######################

KDC_OBJ_FILES = $(addprefix kdc/, kdc.o kpasswdd.o)

#######################
# Start SUBSYSTEM KDC
[SUBSYSTEM::HDB_LDB]
CFLAGS = -Iheimdal/kdc -Iheimdal/lib/hdb
PRIVATE_PROTO_HEADER = pac_glue.h
PRIVATE_DEPENDENCIES = \
		LIBLDB auth_sam auth_sam_reply HEIMDAL CREDENTIALS \
		HEIMDAL_HDB_ASN1
# End SUBSYSTEM KDC
#######################

HDB_LDB_OBJ_FILES = $(addprefix kdc/, hdb-ldb.o pac-glue.o)
