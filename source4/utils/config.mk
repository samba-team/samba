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
		ntlm_check \
		MESSAGING \
		LIBEVENTS
# End BINARY ntlm_auth
#################################

ntlm_auth_OBJ_FILES = $(utilssrcdir)/ntlm_auth.o

MANPAGES += $(utilssrcdir)/man/ntlm_auth.1



#################################
# Start BINARY setnttoken
[BINARY::setnttoken]
INSTALLDIR = BINDIR
PRIVATE_DEPENDENCIES =
# End BINARY setnttoken
#################################

setnttoken_OBJ_FILES = $(utilssrcdir)/setnttoken.o

#################################
# Start BINARY testparm
[BINARY::testparm]
INSTALLDIR = BINDIR
PRIVATE_DEPENDENCIES = \
		LIBSAMBA-HOSTCONFIG \
		LIBSAMBA-UTIL \
		LIBPOPT \
		samba_socket \
		POPT_SAMBA \
		LIBCLI_RESOLVE \
		CHARSET
# End BINARY testparm
#################################

testparm_OBJ_FILES = $(utilssrcdir)/testparm.o

################################################
# Start BINARY oLschema2ldif
[BINARY::oLschema2ldif]
INSTALLDIR = BINDIR
PRIVATE_DEPENDENCIES = \
		LIBLDB_CMDLINE SAMDB
# End BINARY oLschema2ldif
################################################


oLschema2ldif_OBJ_FILES = $(addprefix $(utilssrcdir)/, oLschema2ldif.o)

MANPAGES += $(utilssrcdir)/man/oLschema2ldif.1

