# utils subsystem

#################################
# Start BINARY ntlm_auth
[BINARY::ntlm_auth]
INSTALLDIR = BINDIR
PRIVATE_DEPENDENCIES = \
		LIBSAMBA-HOSTCONFIG \
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

ntlm_auth_OBJ_FILES = utils/ntlm_auth.o

MANPAGES += utils/man/ntlm_auth.1

#################################
# Start BINARY getntacl
[BINARY::getntacl]
INSTALLDIR = BINDIR
PRIVATE_DEPENDENCIES = \
		LIBSAMBA-HOSTCONFIG \
		LIBSAMBA-UTIL \
		NDR_XATTR \
		WRAP_XATTR \
		LIBSAMBA-ERRORS

getntacl_OBJ_FILES = utils/getntacl.o

# End BINARY getntacl
#################################

MANPAGES += utils/man/getntacl.1

#################################
# Start BINARY setntacl
[BINARY::setntacl]
# disabled until rewritten
#INSTALLDIR = BINDIR
# End BINARY setntacl
#################################

setntacl_OBJ_FILES = utils/setntacl.o

#################################
# Start BINARY setnttoken
[BINARY::setnttoken]
INSTALLDIR = BINDIR
PRIVATE_DEPENDENCIES =
# End BINARY setnttoken
#################################

setnttoken_OBJ_FILES = utils/setnttoken.o

#################################
# Start BINARY nmblookup
[BINARY::nmblookup]
INSTALLDIR = BINDIR
PRIVATE_DEPENDENCIES = \
		LIBSAMBA-HOSTCONFIG \
		LIBSAMBA-UTIL \
		LIBCLI_NBT \
		LIBPOPT \
		POPT_SAMBA \
		LIBNETIF \
		LIBCLI_RESOLVE
# End BINARY nmblookup
#################################

nmblookup_OBJ_FILES = utils/nmblookup.o

#################################
# Start BINARY testparm
[BINARY::testparm]
INSTALLDIR = BINDIR
PRIVATE_DEPENDENCIES = \
		LIBSAMBA-HOSTCONFIG \
		LIBSAMBA-UTIL \
		LIBPOPT \
		samba-socket \
		POPT_SAMBA \
		LIBCLI_RESOLVE \
		CHARSET
# End BINARY testparm
#################################

testparm_OBJ_FILES = utils/testparm.o
