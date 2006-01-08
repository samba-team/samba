# TORTURE subsystem

#################################
# Start SUBSYSTEM TORTURE_BASIC
[SUBSYSTEM::TORTURE_BASIC]
OBJ_FILES = \
		basic/scanner.o \
		basic/utable.o \
		basic/charset.o \
		basic/mangle_test.o \
		basic/denytest.o \
		basic/aliases.o \
		basic/locking.o \
		basic/secleak.o \
		basic/rename.o \
		basic/dir.o \
		basic/delete.o \
		basic/unlink.o \
		basic/disconnect.o \
		basic/delaywrite.o \
		basic/attr.o \
		basic/properties.o 
REQUIRED_SUBSYSTEMS = \
		LIBSMB 
# End SUBSYSTEM TORTURE_BASIC
#################################

#################################
# Start SUBSYSTEM TORTURE_RAW
[SUBSYSTEM::TORTURE_RAW]
OBJ_FILES = \
		raw/qfsinfo.o \
		raw/qfileinfo.o \
		raw/setfileinfo.o \
		raw/search.o \
		raw/close.o \
		raw/open.o \
		raw/mkdir.o \
		raw/oplock.o \
		raw/notify.o \
		raw/mux.o \
		raw/ioctl.o \
		raw/chkpath.o \
		raw/unlink.o \
		raw/read.o \
		raw/context.o \
		raw/write.o \
		raw/lock.o \
		raw/rename.o \
		raw/eas.o \
		raw/streams.o \
		raw/acls.o \
		raw/seek.o \
		raw/composite.o
REQUIRED_SUBSYSTEMS = \
		LIBSMB LIBCLI_LSA
# End SUBSYSTEM TORTURE_RAW
#################################

include smb2/config.mk

#################################
# Start SUBSYSTEM TORTURE_COM
[SUBSYSTEM::TORTURE_COM]
OBJ_FILES = \
		com/simple.o
REQUIRED_SUBSYSTEMS = \
		COM DCOM
# End SUBSYSTEM TORTURE_COM
#################################

#################################
# Start SUBSYSTEM TORTURE_RPC
[SUBSYSTEM::TORTURE_RPC]
OBJ_FILES = \
		rpc/join.o \
		rpc/lsa.o \
		rpc/lsa_lookup.o \
		rpc/session_key.o \
		rpc/echo.o \
		rpc/dcom.o \
		rpc/dfs.o \
		rpc/drsuapi.o \
		rpc/drsuapi_cracknames.o \
		rpc/dssync.o \
		rpc/spoolss.o \
		rpc/unixinfo.o \
		rpc/samr.o \
		rpc/wkssvc.o \
		rpc/srvsvc.o \
		rpc/svcctl.o \
		rpc/atsvc.o \
		rpc/eventlog.o \
		rpc/epmapper.o \
		rpc/winreg.o \
		rpc/initshutdown.o \
		rpc/oxidresolve.o \
		rpc/remact.o \
		rpc/mgmt.o \
		rpc/scanner.o \
		rpc/autoidl.o \
		rpc/countcalls.o \
		rpc/testjoin.o \
		rpc/schannel.o \
		rpc/netlogon.o \
		rpc/samlogon.o \
		rpc/samsync.o \
		rpc/rot.o \
		rpc/bind.o \
		rpc/dssetup.o \
		rpc/alter_context.o \
		rpc/bench.o
REQUIRED_SUBSYSTEMS = \
		NDR_ALL RPC_NDR_UNIXINFO RPC_NDR_SAMR RPC_NDR_WINREG RPC_NDR_INITSHUTDOWN \
		RPC_NDR_OXIDRESOLVER RPC_NDR_EVENTLOG RPC_NDR_ECHO RPC_NDR_SVCCTL \
		RPC_NDR_MGMT RPC_NDR_NETLOGON RPC_NDR_ATSVC RPC_NDR_DRSUAPI \
		RPC_NDR_LSA RPC_NDR_EPMAPPER RPC_NDR_DFS RPC_NDR_SPOOLSS \
		RPC_NDR_SRVSVC RPC_NDR_WKSSVC RPC_NDR_ROT RPC_NDR_DSSETUP \
		RPC_NDR_REMACT RPC_NDR_OXIDRESOLVER WB_HELPER 
# End SUBSYSTEM TORTURE_RPC
#################################

#################################
# Start SUBSYSTEM TORTURE_RAP
[SUBSYSTEM::TORTURE_RAP]
OBJ_FILES = \
		rap/rap.o
REQUIRED_SUBSYSTEMS = \
		LIBSMB
# End SUBSYSTEM TORTURE_RAP
#################################

#################################
# Start SUBSYSTEM TORTURE_AUTH
[SUBSYSTEM::TORTURE_AUTH]
OBJ_FILES = \
		auth/ntlmssp.o \
		auth/pac.o
REQUIRED_SUBSYSTEMS = \
		LIBSMB GENSEC AUTH
# End SUBSYSTEM TORTURE_AUTH
#################################

include local/config.mk

#################################
# Start SUBSYSTEM TORTURE_NBENCH
[SUBSYSTEM::TORTURE_NBENCH]
OBJ_FILES = \
		nbench/nbio.o \
		nbench/nbench.o
# End SUBSYSTEM TORTURE_NBENCH
#################################

#################################
# Start SUBSYSTEM TORTURE_LDAP
[SUBSYSTEM::TORTURE_LDAP]
OBJ_FILES = \
		ldap/common.o \
		ldap/basic.o \
		ldap/cldap.o \
		ldap/cldapbench.o
REQUIRED_SUBSYSTEMS = \
		LIBCLI_LDAP LIBCLI_CLDAP
# End SUBSYSTEM TORTURE_LDAP
#################################

#################################
# Start SUBSYSTEM TORTURE_NBT
[SUBSYSTEM::TORTURE_NBT]
OBJ_FILES = \
		nbt/query.o \
		nbt/register.o \
		nbt/wins.o \
		nbt/winsbench.o \
		nbt/winsreplication.o \
		nbt/dgram.o
REQUIRED_SUBSYSTEMS = \
		LIBSMB LIBCLI_NBT LIBCLI_WREPL
# End SUBSYSTEM TORTURE_NBT
#################################

#################################
# Start SUBSYSTEM TORTURE_NET
[SUBSYSTEM::TORTURE_NET]
OBJ_FILES = \
		libnet/userinfo.o \
		libnet/userman.o \
		libnet/domain.o \
		libnet/libnet_lookup.o \
		libnet/libnet_user.o \
		libnet/libnet_share.o \
		libnet/libnet_rpc.o
REQUIRED_SUBSYSTEMS = \
		NDR_ALL RPC_NDR_SAMR LIBNET
# End SUBSYSTEM TORTURE_NET
#################################

#################################
# Start BINARY smbtorture
[BINARY::smbtorture]
INSTALLDIR = BINDIR
PRIVATE_PROTO_HEADER = torture.h
OBJ_FILES = \
		torture.o \
		torture_util.o
REQUIRED_SUBSYSTEMS = \
		TORTURE_BASIC \
		TORTURE_RAW \
		TORTURE_SMB2 \
		TORTURE_RPC \
		TORTURE_RAP \
		TORTURE_AUTH \
		TORTURE_LOCAL \
		TORTURE_NBENCH \
		TORTURE_LDAP \
		TORTURE_COM \
		TORTURE_NBT \
		TORTURE_NET \
		CONFIG \
		LIBBASIC \
		LIBPOPT \
		POPT_SAMBA \
		POPT_CREDENTIALS
MANPAGE = man/smbtorture.1
# End BINARY smbtorture
#################################

#################################
# Start BINARY gentest
[BINARY::gentest]
INSTALLDIR = BINDIR
OBJ_FILES = \
		gentest.o \
		torture_util.o
REQUIRED_SUBSYSTEMS = \
		LIBSMB \
		CONFIG \
		LIBBASIC
MANPAGE = man/gentest.1
# End BINARY gentest
#################################

#################################
# Start BINARY masktest
[BINARY::masktest]
INSTALLDIR = BINDIR
OBJ_FILES = \
		masktest.o
REQUIRED_SUBSYSTEMS = \
		LIBSMB \
		CONFIG \
		LIBBASIC
MANPAGE = man/masktest.1
# End BINARY masktest
#################################

#################################
# Start BINARY locktest
[BINARY::locktest]
INSTALLDIR = BINDIR
OBJ_FILES = \
		locktest.o \
		torture_util.o
REQUIRED_SUBSYSTEMS = \
		LIBSMB \
		CONFIG \
		LIBBASIC
MANPAGE = man/locktest.1
# End BINARY locktest
#################################

GCOV_FLAGS = -ftest-coverage -fprofile-arcs
GCOV_LIBS = -lgcov

gcov: 
	@$(MAKE) test \
		CFLAGS="$(CFLAGS) $(GCOV_FLAGS)" \
		LD_FLAGS="$(LD_FLAGS) $(GCOV_FLAGS)" \
		LIBS="$(LIBS) $(GCOV_LIBS)"
	for I in $(sort $(dir $(ALL_OBJS))); \
		do $(GCOV) -p -o $$I $$I/*.c; \
	done
