
################################################
# Start SUBSYSTEM MESSAGING
[SUBSYSTEM::MESSAGING]
OBJ_FILES = \
		messaging.o
PUBLIC_DEPENDENCIES = \
		DB_WRAP \
		NDR_IRPC \
		UNIX_PRIVS \
		UTIL_TDB 
# End SUBSYSTEM MESSAGING
################################################
