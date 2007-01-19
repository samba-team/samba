include ctdb/config.mk

####################
[SUBSYSTEM::CLUSTER]
OBJ_FILES = cluster.o \
		local.o
PRIVATE_DEPENDENCIES = ctdb
