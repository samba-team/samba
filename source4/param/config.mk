[SUBSYSTEM::LIBSAMBA-CONFIG]
OBJ_FILES = loadparm.o \
			generic.o \
			util.o \
			../lib/version.o
PUBLIC_DEPENDENCIES = LIBSAMBA-UTIL 
PRIVATE_DEPENDENCIES = DYNCONFIG LIBREPLACE_EXT CHARSET
PRIVATE_PROTO_HEADER = proto.h

PUBLIC_HEADERS += param/param.h

#################################
# Start SUBSYSTEM share
[SUBSYSTEM::share]
PRIVATE_PROTO_HEADER = share_proto.h
OBJ_FILES = share.o
PRIVATE_DEPENDENCIES = LIBSAMBA-UTIL
# End SUBSYSTEM share
#################################

PUBLIC_HEADERS += param/share.h

################################################
# Start MODULE share_classic
[MODULE::share_classic]
SUBSYSTEM = share
INIT_FUNCTION = share_classic_init
OBJ_FILES = share_classic.o 
PRIVATE_DEPENDENCIES = LIBSAMBA-UTIL
# End MODULE share_classic
################################################

################################################
# Start MODULE share_ldb
[MODULE::share_ldb]
SUBSYSTEM = share
INIT_FUNCTION = share_ldb_init
OBJ_FILES = share_ldb.o 
PRIVATE_DEPENDENCIES = LIBLDB LDB_WRAP
# End MODULE share_ldb
################################################

[SUBSYSTEM::SECRETS]
OBJ_FILES = secrets.o
PRIVATE_DEPENDENCIES = LIBLDB TDB_WRAP UTIL_TDB NDR_SECURITY

[PYTHON::param]
SWIG_FILE = param.i
PRIVATE_DEPENDENCIES = LIBSAMBA-CONFIG
