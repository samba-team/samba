# NBTD server subsystem

#######################
# Start SUBSYSTEM WINSDB
[SUBSYSTEM::WINSDB]
PRIVATE_PROTO_HEADER = wins/winsdb_proto.h
PUBLIC_DEPENDENCIES = \
		LIBLDB
# End SUBSYSTEM WINSDB
#######################

WINSDB_OBJ_FILES = $(addprefix nbt_server/wins/, winsdb.o wins_hook.o)

#######################
# Start MODULE ldb_wins_ldb
[MODULE::ldb_wins_ldb]
SUBSYSTEM = LIBLDB
OUTPUT_TYPE = SHARED_LIBRARY
INIT_FUNCTION = LDB_MODULE(wins_ldb)
PRIVATE_DEPENDENCIES = \
		LIBNETIF LIBSAMBA-HOSTCONFIG LIBSAMBA-UTIL
# End MODULE ldb_wins_ldb
#######################

ldb_wins_ldb_OBJ_FILES = nbt_server/wins/wins_ldb.o

#######################
# Start SUBSYSTEM NBTD_WINS
[SUBSYSTEM::NBTD_WINS]
PRIVATE_PROTO_HEADER = wins/winsserver_proto.h
PRIVATE_DEPENDENCIES = \
		LIBCLI_NBT WINSDB
# End SUBSYSTEM NBTD_WINS
#######################

NBTD_WINS_OBJ_FILES = $(addprefix nbt_server/wins/, winsserver.o winsclient.o winswack.o wins_dns_proxy.o)

#######################
# Start SUBSYSTEM NBTD_DGRAM
[SUBSYSTEM::NBTD_DGRAM]
PRIVATE_PROTO_HEADER = dgram/proto.h
PRIVATE_DEPENDENCIES = \
		LIBCLI_DGRAM
# End SUBSYSTEM NBTD_DGRAM
#######################

NBTD_DGRAM_OBJ_FILES = $(addprefix nbt_server/dgram/, request.o netlogon.o ntlogon.o browse.o)

#######################
# Start SUBSYSTEM NBTD
[SUBSYSTEM::NBT_SERVER]
PRIVATE_PROTO_HEADER = nbt_server_proto.h
PRIVATE_DEPENDENCIES = \
		LIBCLI_NBT NBTD_WINS NBTD_DGRAM 
# End SUBSYSTEM NBTD
#######################

NBT_SERVER_OBJ_FILES = $(addprefix nbt_server/, \
		interfaces.o \
		register.o \
		query.o \
		nodestatus.o \
		defense.o \
		packet.o \
		irpc.o)

[MODULE::service_nbtd]
INIT_FUNCTION = server_service_nbtd_init
SUBSYSTEM = smbd
PRIVATE_DEPENDENCIES = NBT_SERVER process_model

service_nbtd_OBJ_FILES = \
		nbt_server/nbt_server.o
