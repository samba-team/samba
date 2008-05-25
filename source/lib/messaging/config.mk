[SUBSYSTEM::MESSAGING]
PUBLIC_DEPENDENCIES = \
		LIBSAMBA-UTIL \
		TDB_WRAP \
		NDR_IRPC \
		UNIX_PRIVS \
		UTIL_TDB \
		CLUSTER \
		LIBNDR \
		samba-socket

MESSAGING_OBJ_FILES = $(libmessagingsrcdir)/messaging.o

[PYTHON::python_irpc]
LIBRARY_REALNAME = samba/irpc.$(SHLIBEXT)
PRIVATE_DEPENDENCIES = MESSAGING LIBEVENTS

python_irpc_OBJ_FILES = $(libmessagingsrcdir)/pyirpc.o
