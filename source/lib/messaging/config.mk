
################################################
# Start SUBSYSTEM MESSAGING
[SUBSYSTEM::MESSAGING]
OBJ_FILES = \
		messaging.o
PUBLIC_DEPENDENCIES = \
		NDR_IRPC \
		UNIX_PRIVS
# End SUBSYSTEM MESSAGING
################################################
