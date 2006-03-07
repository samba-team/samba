# utils subsystem

#################################
# Start BINARY ndrdump
[BINARY::ndrdump]
INSTALLDIR = BINDIR
OBJ_FILES = \
		ndrdump.o
REQUIRED_SUBSYSTEMS = \
		CONFIG \
		LIBBASIC \
		NDR_ALL \
		LIBPOPT \
		POPT_SAMBA
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
		LIBBASIC \
		LIBPOPT \
		POPT_SAMBA
MANPAGE = man/ntlm_auth.1
# End BINARY ntlm_auth
#################################

#################################
# Start BINARY getntacl
[BINARY::getntacl]
MANPAGE = man/getntacl.1
INSTALLDIR = BINDIR
OBJ_FILES = \
		getntacl.o
REQUIRED_SUBSYSTEMS = \
		CONFIG \
		LIBBASIC \
		NDR_XATTR \
		EXT_LIB_XATTR
# End BINARY getntacl
#################################

#################################
# Start BINARY setntacl
[BINARY::setntacl]
# disabled until rewritten
#INSTALLDIR = BINDIR
OBJ_FILES = \
		setntacl.o
REQUIRED_SUBSYSTEMS =
# End BINARY setntacl
#################################

#################################
# Start BINARY setnttoken
[BINARY::setnttoken]
INSTALLDIR = BINDIR
OBJ_FILES = \
		setnttoken.o
REQUIRED_SUBSYSTEMS =
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
		LIBBASIC \
		LIBCLI_NBT \
		LIBPOPT \
		POPT_SAMBA \
		LIBNETIF
# End BINARY nmblookup
#################################

#################################
# Start BINARY testparm
[BINARY::testparm]
INSTALLDIR = BINDIR
OBJ_FILES = \
		testparm.o
REQUIRED_SUBSYSTEMS = \
		CONFIG \
		LIBBASIC \
		LIBPOPT \
		SOCKET \
		POPT_SAMBA
# End BINARY testparm
#################################
