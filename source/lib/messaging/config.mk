
################################################
# Start SUBSYSTEM MESSAGING
[SUBSYSTEM::MESSAGING]
OBJ_FILES = \
		messaging.o
NOPROTO = YES
REQUIRED_SUBSYSTEMS = \
		NDR_IRPC \
		UNIX_PRIVS
# End SUBSYSTEM MESSAGING
################################################
