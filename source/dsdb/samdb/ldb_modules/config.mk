################################################
# Start MODULE libldb_objectguid
[MODULE::libldb_objectguid]
SUBSYSTEM = LIBLDB
OBJ_FILES = \
		objectguid.o
REQUIRED_SUBSYSTEMS = \
		LIBNDR NDR_MISC
# End MODULE libldb_objectguid
################################################

################################################
# Start MODULE libldb_samldb
[MODULE::libldb_samldb]
SUBSYSTEM = LIBLDB
OBJ_FILES = \
		samldb.o
#
# End MODULE libldb_samldb
################################################

################################################
# Start MODULE libldb_samba3sam
[MODULE::libldb_samba3sam]
SUBSYSTEM = LIBLDB
OBJ_FILES = \
		samba3sam.o
#
# End MODULE libldb_samldb
################################################

################################################
# Start MODULE libldb_proxy
[MODULE::libldb_proxy]
SUBSYSTEM = LIBLDB
OBJ_FILES = \
		proxy.o
#
# End MODULE libldb_proxy
################################################


################################################
# Start MODULE libldb_rootdse
[MODULE::libldb_rootdse]
SUBSYSTEM = LIBLDB
OBJ_FILES = \
		rootdse.o
#
# End MODULE libldb_rootdse
################################################

