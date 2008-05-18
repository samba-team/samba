ctdbsrcdir = $(clustersrcdir)/ctdb
mkinclude ctdb/config.mk

[SUBSYSTEM::CLUSTER]
PRIVATE_DEPENDENCIES = ctdb

CLUSTER_OBJ_FILES = $(addprefix $(clustersrcdir)/, cluster.o local.o)
