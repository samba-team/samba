# KDC server subsystem

#######################
# Start SUBSYSTEM KDC
[SUBSYSTEM::KDC]
INIT_OBJ_FILES = \
		kdc/kdc.o \
		kdc/pac-glue.o \
		kdc/hdb-ldb.o
REQUIRED_SUBSYSTEMS = \
		LIBLDB KERBEROS_LIB HEIMDAL_KDC HEIMDAL_HDB 
# End SUBSYSTEM KDC
#######################
