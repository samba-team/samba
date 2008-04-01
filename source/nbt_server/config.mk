# NBTD server subsystem

#######################
# Start SUBSYSTEM WINSDB
[SUBSYSTEM::WINSDB]
OBJ_FILES = \
		wins/winsdb.o \
		wins/wins_hook.o
PRIVATE_PROTO_HEADER = wins/winsdb_proto.h
PUBLIC_DEPENDENCIES = \
		LIBLDB
# End SUBSYSTEM WINSDB
#######################

#######################
# Start MODULE ldb_wins_ldb
[MODULE::ldb_wins_ldb]
SUBSYSTEM = LIBLDB
OUTPUT_TYPE = SHARED_LIBRARY
INIT_FUNCTION = &ldb_wins_ldb_module_ops
OBJ_FILES = \
		wins/wins_ldb.o
PRIVATE_DEPENDENCIES = \
		LIBNETIF LIBSAMBA-HOSTCONFIG LIBSAMBA-UTIL
# End MODULE ldb_wins_ldb
#######################

#######################
# Start SUBSYSTEM NBTD_WINS
[SUBSYSTEM::NBTD_WINS]
OBJ_FILES = \
		wins/winsserver.o \
		wins/winsclient.o \
		wins/winswack.o \
		wins/wins_dns_proxy.o
PRIVATE_PROTO_HEADER = wins/winsserver_proto.h
PRIVATE_DEPENDENCIES = \
		LIBCLI_NBT WINSDB
# End SUBSYSTEM NBTD_WINS
#######################

#######################
# Start SUBSYSTEM NBTD_DGRAM
[SUBSYSTEM::NBTD_DGRAM]
PRIVATE_PROTO_HEADER = dgram/proto.h
OBJ_FILES = \
		dgram/request.o \
		dgram/netlogon.o \
		dgram/ntlogon.o \
		dgram/browse.o
PRIVATE_DEPENDENCIES = \
		LIBCLI_DGRAM
# End SUBSYSTEM NBTD_DGRAM
#######################

#######################
# Start SUBSYSTEM NBTD
[SUBSYSTEM::NBT_SERVER]
OBJ_FILES = \
		interfaces.o \
		register.o \
		query.o \
		nodestatus.o \
		defense.o \
		packet.o \
		irpc.o
PRIVATE_PROTO_HEADER = nbt_server_proto.h
PRIVATE_DEPENDENCIES = \
		LIBCLI_NBT NBTD_WINS NBTD_DGRAM 
# End SUBSYSTEM NBTD
#######################

[MODULE::service_nbtd]
INIT_FUNCTION = server_service_nbtd_init
SUBSYSTEM = service
OBJ_FILES = \
		nbt_server.o
PRIVATE_DEPENDENCIES = NBT_SERVER process_model
