
################################################
# Start SUBSYSTEM MESSAGING
[SUBSYSTEM::MESSAGING]
INIT_OBJ_FILES = \
		messaging.o
# \
#		msgutil.o
NOPROTO = YES
REQUIRED_SUBSYSTEMS = \
		NDR_IRPC \
		UNIX_PRIVS
# End SUBSYSTEM MESSAGING
################################################
