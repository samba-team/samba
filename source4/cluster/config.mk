mkinclude ctdb/config.mk

[SUBSYSTEM::CLUSTER]
PRIVATE_DEPENDENCIES = ctdb

CLUSTER_OBJ_FILES = cluster/cluster.o cluster/local.o
