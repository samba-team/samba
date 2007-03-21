# TORTURE subsystem
[LIBRARY::torture]
DESCRIPTION = Samba torture (test) suite
SO_VERSION = 0
VERSION = 0.0.1
PUBLIC_HEADERS = torture.h ui.h
PUBLIC_PROTO_HEADER = proto.h
OBJ_FILES = \
		torture.o \
		ui.o
PUBLIC_DEPENDENCIES = \
		LIBSAMBA-CONFIG \
		LIBSAMBA-UTIL \
		LIBTALLOC 

[SUBSYSTEM::TORTURE_UTIL]
OBJ_FILES = util.o util_smb.o
PRIVATE_DEPENDENCIES = LIBCLI_RAW
PUBLIC_PROTO_HEADER = util.h
PUBLIC_DEPENDENCIES = POPT_CREDENTIALS

#################################
# Start SUBSYSTEM TORTURE_BASIC
[MODULE::TORTURE_BASIC]
SUBSYSTEM = torture
INIT_FUNCTION = torture_base_init
PRIVATE_PROTO_HEADER = \
		basic/proto.h
OBJ_FILES = \
		basic/base.o \
		basic/misc.o \
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
PUBLIC_DEPENDENCIES = \
		LIBCLI_SMB POPT_CREDENTIALS \
		TORTURE_UTIL LIBCLI_RAW
PRIVATE_DEPENDENCIES = TORTURE_RAW
# End SUBSYSTEM TORTURE_BASIC
#################################

#################################
# Start SUBSYSTEM TORTURE_RAW
[MODULE::TORTURE_RAW]
SUBSYSTEM = torture
INIT_FUNCTION = torture_raw_init
PRIVATE_PROTO_HEADER = \
		raw/proto.h
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
		raw/lockbench.o \
		raw/rename.o \
		raw/eas.o \
		raw/streams.o \
		raw/acls.o \
		raw/seek.o \
		raw/samba3hide.o \
		raw/samba3misc.o \
		raw/composite.o \
		raw/raw.o
PUBLIC_DEPENDENCIES = \
		LIBCLI_SMB LIBCLI_LSA LIBCLI_SMB_COMPOSITE \
		POPT_CREDENTIALS
PRIVATE_DEPENDENCIES = TORTURE_UTIL
# End SUBSYSTEM TORTURE_RAW
#################################

include smb2/config.mk

[SUBSYSTEM::TORTURE_NDR]
PRIVATE_PROTO_HEADER = ndr/proto.h
OBJ_FILES = ndr/ndr.o \
			ndr/winreg.o \
			ndr/atsvc.o \
			ndr/lsa.o \
			ndr/epmap.o \
			ndr/dfs.o \
			ndr/netlogon.o \
			ndr/drsuapi.o \
			ndr/spoolss.o \
			ndr/samr.o

[MODULE::torture_rpc]
# TORTURE_NET and TORTURE_NBT use functions from torture_rpc...
#OUTPUT_TYPE = INTEGRATED
SUBSYSTEM = torture
INIT_FUNCTION = torture_rpc_init
PRIVATE_PROTO_HEADER = \
		rpc/proto.h
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
		rpc/bench.o \
		rpc/samba3rpc.o \
		rpc/rpc.o \
		rpc/async_bind.o \
		rpc/handles.o
PUBLIC_DEPENDENCIES = \
		NDR_TABLE RPC_NDR_UNIXINFO dcerpc_samr RPC_NDR_WINREG RPC_NDR_INITSHUTDOWN \
		RPC_NDR_OXIDRESOLVER RPC_NDR_EVENTLOG RPC_NDR_ECHO RPC_NDR_SVCCTL \
		RPC_NDR_NETLOGON dcerpc_atsvc dcerpc_mgmt RPC_NDR_DRSUAPI \
		RPC_NDR_LSA RPC_NDR_EPMAPPER RPC_NDR_DFS RPC_NDR_SPOOLSS \
		RPC_NDR_SRVSVC RPC_NDR_WKSSVC RPC_NDR_ROT RPC_NDR_DSSETUP \
		RPC_NDR_REMACT RPC_NDR_OXIDRESOLVER WB_HELPER LIBSAMBA-NET \
		LIBCLI_AUTH POPT_CREDENTIALS
PRIVATE_DEPENDENCIES = TORTURE_LDAP TORTURE_UTIL TORTURE_RAP

#################################
# Start SUBSYSTEM TORTURE_RAP
[MODULE::TORTURE_RAP]
SUBSYSTEM = torture
INIT_FUNCTION = torture_rap_init
PRIVATE_PROTO_HEADER = \
		rap/proto.h
OBJ_FILES = \
		rap/rap.o
PRIVATE_DEPENDENCIES = TORTURE_UTIL
PUBLIC_DEPENDENCIES = \
		LIBCLI_SMB
# End SUBSYSTEM TORTURE_RAP
#################################

#################################
# Start SUBSYSTEM TORTURE_AUTH
[MODULE::TORTURE_AUTH]
SUBSYSTEM = torture
PRIVATE_PROTO_HEADER = \
		auth/proto.h
OBJ_FILES = \
		auth/ntlmssp.o \
		auth/pac.o
PUBLIC_DEPENDENCIES = \
		LIBCLI_SMB gensec auth LIBSAMBA3 KERBEROS \
		POPT_CREDENTIALS
# End SUBSYSTEM TORTURE_AUTH
#################################

include local/config.mk

#################################
# Start MODULE TORTURE_NBENCH
[MODULE::TORTURE_NBENCH]
SUBSYSTEM = torture
INIT_FUNCTION = torture_nbench_init
PRIVATE_DEPENDENCIES = TORTURE_UTIL 
PRIVATE_PROTO_HEADER = \
		nbench/proto.h
OBJ_FILES = \
		nbench/nbio.o \
		nbench/nbench.o
# End MODULE TORTURE_NBENCH
#################################

#################################
# Start MODULE TORTURE_UNIX
[MODULE::TORTURE_UNIX]
SUBSYSTEM = torture
INIT_FUNCTION = torture_unix_init
PRIVATE_DEPENDENCIES = TORTURE_UTIL 
PRIVATE_PROTO_HEADER = \
		unix/proto.h
OBJ_FILES = \
		unix/unix.o \
		unix/whoami.o \
		unix/unix_info2.o
# End MODULE TORTURE_UNIX
#################################

#################################
# Start SUBSYSTEM TORTURE_LDAP
[MODULE::TORTURE_LDAP]
SUBSYSTEM = torture
INIT_FUNCTION = torture_ldap_init
PRIVATE_PROTO_HEADER = \
		ldap/proto.h
OBJ_FILES = \
		ldap/common.o \
		ldap/basic.o \
		ldap/schema.o \
		ldap/uptodatevector.o \
		ldap/cldap.o \
		ldap/cldapbench.o
PUBLIC_DEPENDENCIES = \
		LIBCLI_LDAP LIBCLI_CLDAP SAMDB POPT_CREDENTIALS
# End SUBSYSTEM TORTURE_LDAP
#################################

#################################
# Start SUBSYSTEM TORTURE_NBT
[MODULE::TORTURE_NBT]
SUBSYSTEM = torture
INIT_FUNCTION = torture_nbt_init
PRIVATE_PROTO_HEADER = \
		nbt/proto.h
OBJ_FILES = \
		nbt/query.o \
		nbt/register.o \
		nbt/wins.o \
		nbt/winsbench.o \
		nbt/winsreplication.o \
		nbt/dgram.o \
		nbt/nbt.o
PUBLIC_DEPENDENCIES = \
		LIBCLI_SMB LIBCLI_NBT LIBCLI_DGRAM LIBCLI_WREPL
PRIVATE_DEPENDENCIES = torture_rpc
# End SUBSYSTEM TORTURE_NBT
#################################

#################################
# Start SUBSYSTEM TORTURE_NET
[MODULE::TORTURE_NET]
SUBSYSTEM = torture
INIT_FUNCTION = torture_net_init
PRIVATE_PROTO_HEADER = \
		libnet/proto.h
OBJ_FILES = \
		libnet/libnet.o \
		libnet/userinfo.o \
		libnet/userman.o \
		libnet/domain.o \
		libnet/libnet_lookup.o \
		libnet/libnet_user.o \
		libnet/libnet_share.o \
		libnet/libnet_rpc.o \
		libnet/libnet_domain.o \
		libnet/libnet_BecomeDC.o
PUBLIC_DEPENDENCIES = \
		LIBSAMBA-NET \
		smbcalls \
		POPT_CREDENTIALS
PRIVATE_DEPENDENCIES = torture_rpc
# End SUBSYSTEM TORTURE_NET
#################################

#################################
# Start BINARY smbtorture
[BINARY::smbtorture]
INSTALLDIR = BINDIR
OBJ_FILES = \
		smbtorture.o
PRIVATE_DEPENDENCIES = \
		torture \
		LIBPOPT \
		POPT_SAMBA \
		POPT_CREDENTIALS \
		dcerpc \
		LIBCLI_SMB \
		SMBREADLINE
MANPAGE = man/smbtorture.1
# End BINARY smbtorture
#################################

#################################
# Start BINARY gentest
[BINARY::gentest]
INSTALLDIR = BINDIR
OBJ_FILES = \
		gentest.o
PRIVATE_DEPENDENCIES = \
		LIBSAMBA-CONFIG \
		LIBSAMBA-UTIL \
		LIBPOPT \
		POPT_SAMBA \
		POPT_CREDENTIALS \
		LIBCLI_SMB \
		LIBCLI_RAW
MANPAGE = man/gentest.1
# End BINARY gentest
#################################

#################################
# Start BINARY masktest
[BINARY::masktest]
INSTALLDIR = BINDIR
OBJ_FILES = \
		masktest.o
PRIVATE_DEPENDENCIES = \
		LIBSAMBA-CONFIG \
		LIBSAMBA-UTIL \
		LIBPOPT \
		POPT_SAMBA \
		POPT_CREDENTIALS \
		LIBCLI_SMB
MANPAGE = man/masktest.1
# End BINARY masktest
#################################

#################################
# Start BINARY locktest
[BINARY::locktest]
INSTALLDIR = BINDIR
OBJ_FILES = \
		locktest.o
PRIVATE_DEPENDENCIES = \
		LIBSAMBA-UTIL \
		LIBCLI_SMB \
		LIBSAMBA-CONFIG
MANPAGE = man/locktest.1
# End BINARY locktest
#################################

GCOV_FLAGS = -ftest-coverage -fprofile-arcs
GCOV_LIBS = -lgcov

COV_TARGET = test

test_cov:
	@$(MAKE) $(COV_TARGET) \
		HOSTCC_CFLAGS="$(HOSTCC_CFLAGS) $(GCOV_FLAGS)" \
		CFLAGS="$(CFLAGS) $(GCOV_FLAGS)" \
		LDFLAGS="$(LDFLAGS) $(GCOV_FLAGS) $(GCOV_LIBS)" \
		SHLD_FLAGS="$(SHLD_FLAGS) $(GCOV_FLAGS) $(GCOV_LIBS)"

gcov: test_cov
	for I in $(sort $(dir $(ALL_OBJS))); \
		do $(GCOV) -p -o $$I $$I/*.c; \
	done

lcov-split: 
	rm -f samba.info
	@$(MAKE) $(COV_TARGET) \
		HOSTCC_CFLAGS="$(HOSTCC_CFLAGS) $(GCOV_FLAGS)" \
		CFLAGS="$(CFLAGS) $(GCOV_FLAGS)" \
		LDFLAGS="$(LDFLAGS) $(GCOV_FLAGS) $(GCOV_LIBS)" \
		SHLD_FLAGS="$(SHLD_FLAGS) $(GCOV_FLAGS) $(GCOV_LIBS)" \
		TEST_OPTIONS="--analyse-cmd=\"lcov --base-directory `pwd` --directory . --capture --output-file samba.info -t\""
	-rm heimdal/lib/*/{lex,parse}.{gcda,gcno}
	genhtml -o coverage samba.info

lcov: test_cov
	-rm heimdal/lib/*/{lex,parse}.{gcda,gcno}
	lcov --base-directory `pwd` --directory . --capture --output-file samba.info
	genhtml -o coverage samba.info

testcov-html:: lcov
