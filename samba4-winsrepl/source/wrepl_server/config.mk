# WREPL server subsystem

#######################
# Start SUBSYSTEM WREPL_SRV
[SUBSYSTEM::WREPL_SRV]
INIT_OBJ_FILES = \
		wrepl_server/wrepl_server.o
REQUIRED_SUBSYSTEMS = \
		LIBCLI_WREPL WINSDB
# End SUBSYSTEM WREPL_SRV
#######################
