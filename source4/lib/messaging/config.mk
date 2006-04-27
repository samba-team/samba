
################################################
# Start SUBSYSTEM MESSAGING
[SUBSYSTEM::MESSAGING]
OBJ_FILES = \
		messaging.o
PUBLIC_DEPENDENCIES = \
		DB_WRAP \
		NDR_IRPC \
		UNIX_PRIVS
# End SUBSYSTEM MESSAGING
################################################
