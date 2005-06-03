# CLDAP server subsystem

#######################
# Start SUBSYSTEM CLDAPD
[SUBSYSTEM::KDC]
INIT_OBJ_FILES = \
		kdc/kdc.o \
		kdc/hdb-ldb.o
REQUIRED_SUBSYSTEMS = \
		SOCKET
# End SUBSYSTEM CLDAPD
#######################
