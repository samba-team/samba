# KDC server subsystem

#######################
# Start SUBSYSTEM KDC
[SUBSYSTEM::KDC]
INIT_OBJ_FILES = \
		kdc.o \
		pac-glue.o \
		hdb-ldb.o \
		kpasswdd.o
REQUIRED_SUBSYSTEMS = \
		LIBLDB KERBEROS_LIB HEIMDAL_KDC HEIMDAL_HDB 
# End SUBSYSTEM KDC
#######################
