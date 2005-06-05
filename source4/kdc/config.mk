# KDC server subsystem

#######################
# Start SUBSYSTEM KDC
[SUBSYSTEM::KDC]
INIT_OBJ_FILES = \
		kdc/kdc.o \
		kdc/hdb-ldb.o
REQUIRED_SUBSYSTEMS = \
		LDB EXT_LIB_KRB5 EXT_LIB_KDC
# End SUBSYSTEM KDC
#######################
