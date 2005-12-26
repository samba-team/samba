# NBTD server subsystem

#######################
# Start SUBSYSTEM WINSDB
[SUBSYSTEM::WINSDB]
OBJ_FILES = \
		wins/winsdb.o
REQUIRED_SUBSYSTEMS = \
		LIBLDB
# End SUBSYSTEM WINSDB
#######################

#######################
# Start SUBSYSTEM NBTD_WINS
[SUBSYSTEM::NBTD_WINS]
OBJ_FILES = \
		wins/winsserver.o \
		wins/winsclient.o \
		wins/winswack.o
REQUIRED_SUBSYSTEMS = \
		LIBCLI_NBT WINSDB
# End SUBSYSTEM NBTD_WINS
#######################

#######################
# Start SUBSYSTEM NBTD_DGRAM
[SUBSYSTEM::NBTD_DGRAM]
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
REQUIRED_SUBSYSTEMS = \
		LIBCLI_NBT NBTD_WINS NBTD_DGRAM
# End SUBSYSTEM NBTD
#######################
