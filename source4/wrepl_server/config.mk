# WREPL server subsystem

#######################
# Start SUBSYSTEM WREPL_SRV
[SUBSYSTEM::WREPL_SRV]
INIT_OBJ_FILES = \
		wrepl_server.o \
		wrepl_in_connection.o \
		wrepl_in_call.o \
		wrepl_out_connection.o \
		wrepl_out_helpers.o \
		wrepl_apply_records.o \
		wrepl_periodic.o
REQUIRED_SUBSYSTEMS = \
		LIBCLI_WREPL WINSDB
# End SUBSYSTEM WREPL_SRV
#######################
