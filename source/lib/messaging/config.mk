
################################################
# Start SUBSYSTEM MESSAGING
[SUBSYSTEM::MESSAGING]
PUBLIC_DEPENDENCIES = \
		LIBSAMBA-UTIL \
		TDB_WRAP \
		NDR_IRPC \
		UNIX_PRIVS \
		UTIL_TDB \
		CLUSTER \
		LIBNDR
# End SUBSYSTEM MESSAGING
################################################


MESSAGING_OBJ_FILES = lib/messaging/messaging.o
