# KDC server subsystem

#######################
# Start SUBSYSTEM KDC
[SUBSYSTEM::KDC]
OBJ_FILES = \
		kdc.o \
		kpasswdd.o
REQUIRED_SUBSYSTEMS = \
		ldb KERBEROS_LIB HEIMDAL_KDC HEIMDAL_HDB 
# End SUBSYSTEM KDC
#######################

#######################
# Start SUBSYSTEM KDC
[SUBSYSTEM::HDB_LDB]
OBJ_FILES = \
		hdb-ldb.o \
		pac-glue.o 
REQUIRED_SUBSYSTEMS = \
		ldb KERBEROS_LIB HEIMDAL_HDB 
# End SUBSYSTEM KDC
#######################

