# NBTD server subsystem

#######################
# Start SUBSYSTEM NBTD
[SUBSYSTEM::NBTD]
INIT_OBJ_FILES = \
		nbt_server/nbt_server.o
ADD_OBJ_FILES = \
		nbt_server/interfaces.o
REQUIRED_SUBSYSTEMS = \
		LIBCLI_NBT
# End SUBSYSTEM SMB
#######################
