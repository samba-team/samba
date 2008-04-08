[LIBRARY::LIBSAMBA-HOSTCONFIG]
VERSION = 0.0.1
SO_VERSION = 1
PUBLIC_DEPENDENCIES = LIBSAMBA-UTIL 
PRIVATE_DEPENDENCIES = DYNCONFIG LIBREPLACE_EXT CHARSET
PRIVATE_PROTO_HEADER = proto.h

LIBSAMBA-CONFIG_OBJ_FILES = param/loadparm.o \
			param/params.o \
			param/generic.o \
			param/util.o \
			lib/version.o

PUBLIC_HEADERS += param/param.h

PC_FILES += param/samba-hostconfig.pc

#################################
# Start SUBSYSTEM share
[SUBSYSTEM::share]
PRIVATE_PROTO_HEADER = share_proto.h
PRIVATE_DEPENDENCIES = LIBSAMBA-UTIL
# End SUBSYSTEM share
#################################

share_OBJ_FILES = param/share.o

PUBLIC_HEADERS += param/share.h

################################################
# Start MODULE share_classic
[MODULE::share_classic]
SUBSYSTEM = share
INIT_FUNCTION = share_classic_init
PRIVATE_DEPENDENCIES = LIBSAMBA-UTIL
# End MODULE share_classic
################################################

share_classic_OBJ_FILES = param/share_classic.o 

################################################
# Start MODULE share_ldb
[MODULE::share_ldb]
SUBSYSTEM = share
INIT_FUNCTION = share_ldb_init
PRIVATE_DEPENDENCIES = LIBLDB LDB_WRAP
# End MODULE share_ldb
################################################

share_ldb_OBJ_FILES = param/share_ldb.o 

[SUBSYSTEM::SECRETS]
PRIVATE_DEPENDENCIES = LIBLDB TDB_WRAP UTIL_TDB NDR_SECURITY

SECRETS_OBJ_FILES = param/secrets.o

[PYTHON::param]
SWIG_FILE = param.i
PRIVATE_DEPENDENCIES = LIBSAMBA-HOSTCONFIG

param_OBJ_FILES = param/param_wrap.o
