# NBTD server subsystem

#######################
# Start SUBSYSTEM NBTD_WINS
[SUBSYSTEM::NBTD_WINS]
ADD_OBJ_FILES = \
		nbt_server/wins/winsserver.o \
		nbt_server/wins/winsclient.o \
		nbt_server/wins/winsdb.o \
		nbt_server/wins/winswack.o
REQUIRED_SUBSYSTEMS = \
		LIBCLI_NBT LIBCLI_WINS
# End SUBSYSTEM NBTD_WINS
#######################

#######################
# Start SUBSYSTEM NBTD_DGRAM
[SUBSYSTEM::NBTD_DGRAM]
ADD_OBJ_FILES = \
		nbt_server/dgram/request.o \
		nbt_server/dgram/netlogon.o \
		nbt_server/dgram/browse.o
REQUIRED_SUBSYSTEMS = \
		LIBCLI_DGRAM
# End SUBSYSTEM NBTD_DGRAM
#######################

#######################
# Start SUBSYSTEM NBTD
[SUBSYSTEM::NBTD]
INIT_OBJ_FILES = \
		nbt_server/nbt_server.o
ADD_OBJ_FILES = \
		nbt_server/interfaces.o \
		nbt_server/register.o \
		nbt_server/query.o \
		nbt_server/nodestatus.o \
		nbt_server/defense.o \
		nbt_server/packet.o
REQUIRED_SUBSYSTEMS = \
		LIBCLI_NBT NBTD_WINS NBTD_DGRAM
# End SUBSYSTEM NBTD
#######################
