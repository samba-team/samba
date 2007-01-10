# KDC server subsystem

#######################
# Start SUBSYSTEM KDC
[MODULE::KDC]
INIT_FUNCTION = server_service_kdc_init
SUBSYSTEM = service
OBJ_FILES = \
		kdc.o \
		kpasswdd.o
PUBLIC_DEPENDENCIES = \
		ldb KERBEROS_LIB HEIMDAL_KDC HEIMDAL_HDB SAMDB
# End SUBSYSTEM KDC
#######################

#######################
# Start SUBSYSTEM KDC
[SUBSYSTEM::HDB_LDB]
CFLAGS = -Iheimdal/kdc -Iheimdal/lib/hdb
PUBLIC_PROTO_HEADER = pac_glue.h
OBJ_FILES = \
		hdb-ldb.o \
		pac-glue.o 
PUBLIC_DEPENDENCIES = \
		ldb auth_sam KERBEROS
# End SUBSYSTEM KDC
#######################

