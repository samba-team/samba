[BINARY::swig_tdb]
OBJ_FILES = scripting/swig/dummymain.o
REQUIRED_SUBSYSTEMS = LIBTDB

[BINARY::swig_dcerpc]
OBJ_FILES = scripting/swig/dummymain.o
REQUIRED_SUBSYSTEMS = LIBCLI NDR_MISC LIBBASIC CONFIG RPC_NDR_SAMR
