# NBTD server subsystem

#######################
# Start SUBSYSTEM NBTD
[SUBSYSTEM::NBTD]
INIT_OBJ_FILES = \
		nbt_server/nbt_server.o
ADD_OBJ_FILES = \
		nbt_server/interfaces.o \
		nbt_server/register.o \
		nbt_server/query.o \
		nbt_server/winsserver.o \
		nbt_server/packet.o
REQUIRED_SUBSYSTEMS = \
		LIBCLI_NBT
# End SUBSYSTEM SMB
#######################
