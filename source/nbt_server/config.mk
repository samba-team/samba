# NBTD server subsystem

#######################
# Start SUBSYSTEM WINSDB
[SUBSYSTEM::WINSDB]
OBJ_FILES = \
		wins/winsdb.o \
		wins/wins_hook.o
PRIVATE_PROTO_HEADER = wins/winsdb_proto.h
REQUIRED_SUBSYSTEMS = \
		LIBLDB
# End SUBSYSTEM WINSDB
#######################

#######################
# Start MODULE libldb_wins_ldb
[MODULE::libldb_wins_ldb]
SUBSYSTEM = LIBLDB
INIT_FUNCTION = wins_ldb_module_init
OBJ_FILES = \
		wins/wins_ldb.o
REQUIRED_SUBSYSTEMS = \
		LIBNETIF
# End MODULE libldb_wins_ldb
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
REQUIRED_SUBSYSTEMS = \
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
REQUIRED_SUBSYSTEMS = \
		LIBCLI_DGRAM
# End SUBSYSTEM NBTD_DGRAM
#######################

#######################
# Start SUBSYSTEM NBTD
[SUBSYSTEM::NBTD]
OBJ_FILES = \
		nbt_server.o \
		interfaces.o \
		register.o \
		query.o \
		nodestatus.o \
		defense.o \
		packet.o \
		irpc.o
PRIVATE_PROTO_HEADER = nbt_server_proto.h
REQUIRED_SUBSYSTEMS = \
		LIBCLI_NBT NBTD_WINS NBTD_DGRAM
# End SUBSYSTEM NBTD
#######################
