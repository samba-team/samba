
################################################
# Start SUBSYSTEM MESSAGING
[SUBSYSTEM::MESSAGING]
INIT_OBJ_FILES = \
		lib/messaging/messaging.o
# \
#		lib/messaging/msgutil.o
NOPROTO = YES
REQUIRED_SUBSYSTEMS = \
		NDR_IRPC \
		UNIX_PRIVS
# End SUBSYSTEM MESSAGING
################################################
