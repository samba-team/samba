
################################################
# Start SUBSYSTEM MESSAGING
[SUBSYSTEM::MESSAGING]
INIT_OBJ_FILES = \
		lib/messaging/messaging.o
NOPROTO = YES
REQUIRED_SUBSYSTEMS = \
		NDR_IRPC
# End SUBSYSTEM MESSAGING
################################################
