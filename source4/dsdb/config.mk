# Directory Service subsystem

################################################
# Start SUBSYSTEM SAMDB
[SUBSYSTEM::SAMDB]
INIT_OBJ_FILES = \
		dsdb/samdb/samdb.o
ADD_OBJ_FILES = \
		dsdb/common/flag_mapping.o
REQUIRED_SUBSYSTEMS = \
		DCERPC_COMMON \
		LIBLDB
#
# End SUBSYSTEM SAMDB
################################################
