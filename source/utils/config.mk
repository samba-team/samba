# utils subsystem

#################################
# Start BINARY ndrdump
[BINARY::ndrdump]
INSTALLDIR = BINDIR
OBJ_FILES = \
		ndrdump.o
REQUIRED_SUBSYSTEMS = \
		CONFIG \
		LIBCMDLINE \
		LIBBASIC \
		NDR_ALL \
		LIBRPC
MANPAGE = man/ndrdump.1
# FIXME: ndrdump shouldn't have to depend on RPC...
# End BINARY ndrdump
#################################

#################################
# Start BINARY ntlm_auth
[BINARY::ntlm_auth]
INSTALLDIR = BINDIR
OBJ_FILES = \
		ntlm_auth.o
REQUIRED_SUBSYSTEMS = \
		CONFIG \
		LIBCMDLINE \
		LIBBASIC \
		LIBSMB \
		LIBRPC
MANPAGE = man/ntlm_auth.1
# End BINARY ntlm_auth
#################################

#################################
# Start BINARY getntacl
[BINARY::getntacl]
INSTALLDIR = BINDIR
OBJ_FILES = \
		getntacl.o
REQUIRED_SUBSYSTEMS = \
		CONFIG \
		LIBCMDLINE \
		LIBBASIC \
		LIBRPC \
		NDR_XATTR \
		EXT_LIB_XATTR
# End BINARY getntacl
#################################

#################################
# Start BINARY setntacl
[BINARY::setntacl]
INSTALLDIR = BINDIR
OBJ_FILES = \
		setntacl.o
REQUIRED_SUBSYSTEMS = \
		CONFIG \
		LIBCMDLINE \
		LIBBASIC \
		LIBRPC
# End BINARY setntacl
#################################

#################################
# Start BINARY setnttoken
[BINARY::setnttoken]
INSTALLDIR = BINDIR
OBJ_FILES = \
		setnttoken.o
REQUIRED_SUBSYSTEMS = \
		CONFIG \
		LIBCMDLINE \
		LIBBASIC \
		LIBRPC \
		NDR_XATTR \
		NDR_SAMR
# End BINARY setnttoken
#################################

#################################
# Start BINARY nmblookup
[BINARY::nmblookup]
INSTALLDIR = BINDIR
OBJ_FILES = \
		nmblookup.o
REQUIRED_SUBSYSTEMS = \
		CONFIG \
		LIBCMDLINE \
		LIBBASIC \
		LIBCLI_NBT \
		LIB_SECURITY_NDR
# End BINARY nmblookup
#################################
