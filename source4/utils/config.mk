# utils subsystem

#################################
# Start BINARY ntlm_auth
[BINARY::ntlm_auth]
INSTALLDIR = BINDIR
OBJ_FILES = \
		ntlm_auth.o
PRIVATE_DEPENDENCIES = \
		LIBSAMBA-CONFIG \
		LIBSAMBA-UTIL \
		LIBPOPT \
		POPT_SAMBA \
		POPT_CREDENTIALS \
		gensec \
		LIBCLI_RESOLVE \
		auth \
		MESSAGING \
		LIBEVENTS
# End BINARY ntlm_auth
#################################

MANPAGES += utils/man/ntlm_auth.1

#################################
# Start BINARY getntacl
[BINARY::getntacl]
INSTALLDIR = BINDIR
OBJ_FILES = \
		getntacl.o
PRIVATE_DEPENDENCIES = \
		LIBSAMBA-CONFIG \
		LIBSAMBA-UTIL \
		NDR_XATTR \
		WRAP_XATTR \
		LIBSAMBA-ERRORS

# End BINARY getntacl
#################################

MANPAGES += utils/man/getntacl.1

#################################
# Start BINARY setntacl
[BINARY::setntacl]
# disabled until rewritten
#INSTALLDIR = BINDIR
OBJ_FILES = \
		setntacl.o
# End BINARY setntacl
#################################

#################################
# Start BINARY setnttoken
[BINARY::setnttoken]
INSTALLDIR = BINDIR
OBJ_FILES = \
		setnttoken.o
PRIVATE_DEPENDENCIES =
# End BINARY setnttoken
#################################

#################################
# Start BINARY nmblookup
[BINARY::nmblookup]
INSTALLDIR = BINDIR
OBJ_FILES = \
		nmblookup.o
PRIVATE_DEPENDENCIES = \
		LIBSAMBA-CONFIG \
		LIBSAMBA-UTIL \
		LIBCLI_NBT \
		LIBPOPT \
		POPT_SAMBA \
		LIBNETIF \
		LIBCLI_RESOLVE
# End BINARY nmblookup
#################################

#################################
# Start BINARY testparm
[BINARY::testparm]
INSTALLDIR = BINDIR
OBJ_FILES = \
		testparm.o
PRIVATE_DEPENDENCIES = \
		LIBSAMBA-CONFIG \
		LIBSAMBA-UTIL \
		LIBPOPT \
		samba-socket \
		POPT_SAMBA \
		LIBCLI_RESOLVE \
		CHARSET
# End BINARY testparm
#################################
