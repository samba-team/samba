
################################################
# Start SUBSYSTEM MESSAGING
[SUBSYSTEM::MESSAGING]
OBJ_FILES = \
		messaging.o
PUBLIC_DEPENDENCIES = \
		LIBSAMBA-UTIL \
		TDB_WRAP \
		NDR_IRPC \
		UNIX_PRIVS \
		UTIL_TDB \
		CLUSTER
# End SUBSYSTEM MESSAGING
################################################
