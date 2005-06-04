#######################
# Start LIBRARY SMBCALLS
[SUBSYSTEM::SMBCALLS]
OBJ_FILES = \
		scripting/ejs/smbcalls.o \
		scripting/ejs/smbcalls_config.o \
		scripting/ejs/smbcalls_ldb.o \
		scripting/ejs/smbcalls_nbt.o \
		scripting/ejs/mprutil.o
REQUIRED_SUBSYSTEMS = AUTH EJS LIBBASIC
# End SUBSYSTEM SMBCALLS
#######################

#######################
# Start BINARY SMBSCRIPT
[BINARY::smbscript]
OBJ_FILES = \
		scripting/ejs/smbscript.o
REQUIRED_SUBSYSTEMS = EJS LIBBASIC SMBCALLS CONFIG LIBSMB RPC

# End BINARY SMBSCRIPT
#######################

#######################
# Start LIBRARY swig_tdb
[LIBRARY::swig_tdb]
REQUIRED_SUBSYSTEMS = LIBTDB
# End LIBRARY swig_tdb
#######################

#######################
# Start LIBRARY swig_dcerpc
[LIBRARY::swig_dcerpc]
REQUIRED_SUBSYSTEMS = LIBCLI NDR_MISC LIBBASIC CONFIG RPC_NDR_SAMR RPC_NDR_LSA
# End LIBRARY swig_dcerpc
#######################
