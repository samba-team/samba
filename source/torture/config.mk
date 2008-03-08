# TORTURE subsystem
[LIBRARY::torture]
PC_FILE = torture.pc
PRIVATE_PROTO_HEADER = proto.h
PUBLIC_DEPENDENCIES = \
		LIBSAMBA-CONFIG \
		LIBSAMBA-UTIL \
		LIBTALLOC \
		LIBPOPT

torture_OBJ_FILES = $(addprefix torture/, torture.o ui.o)

PUBLIC_HEADERS += torture/torture.h torture/ui.h

[SUBSYSTEM::TORTURE_UTIL]
PRIVATE_DEPENDENCIES = LIBCLI_RAW LIBPYTHON smbcalls
PUBLIC_DEPENDENCIES = POPT_CREDENTIALS

TORTURE_UTIL_OBJ_FILES = $(addprefix torture/, util_smb.o util_provision.o)

#################################
# Start SUBSYSTEM TORTURE_BASIC
[MODULE::TORTURE_BASIC]
SUBSYSTEM = torture
INIT_FUNCTION = torture_base_init
PRIVATE_PROTO_HEADER = \
		basic/proto.h
PRIVATE_DEPENDENCIES = \
		LIBCLI_SMB POPT_CREDENTIALS \
		TORTURE_UTIL LIBCLI_RAW \
		TORTURE_RAW
# End SUBSYSTEM TORTURE_BASIC
#################################

TORTURE_BASIC_OBJ_FILES = $(addprefix torture/basic/,  \
		base.o \
		misc.o \
		scanner.o \
		utable.o \
		charset.o \
		mangle_test.o \
		denytest.o \
		aliases.o \
		locking.o \
		secleak.o \
		rename.o \
		dir.o \
		delete.o \
		unlink.o \
		disconnect.o \
		delaywrite.o \
		attr.o \
		properties.o)


#################################
# Start SUBSYSTEM TORTURE_RAW
[MODULE::TORTURE_RAW]
SUBSYSTEM = torture
INIT_FUNCTION = torture_raw_init
PRIVATE_PROTO_HEADER = \
		raw/proto.h
PRIVATE_DEPENDENCIES = \
		LIBCLI_SMB LIBCLI_LSA LIBCLI_SMB_COMPOSITE \
		POPT_CREDENTIALS TORTURE_UTIL
# End SUBSYSTEM TORTURE_RAW
#################################

TORTURE_RAW_OBJ_FILES = $(addprefix torture/raw/, \
		qfsinfo.o \
		qfileinfo.o \
		setfileinfo.o \
		search.o \
		close.o \
		open.o \
		mkdir.o \
		oplock.o \
		notify.o \
		mux.o \
		ioctl.o \
		chkpath.o \
		unlink.o \
		read.o \
		context.o \
		write.o \
		lock.o \
		pingpong.o \
		lockbench.o \
		openbench.o \
		rename.o \
		eas.o \
		streams.o \
		acls.o \
		seek.o \
		samba3hide.o \
		samba3misc.o \
		composite.o \
		raw.o \
		offline.o)


mkinclude smb2/config.mk
mkinclude winbind/config.mk

[SUBSYSTEM::TORTURE_NDR]
PRIVATE_PROTO_HEADER = ndr/proto.h

TORTURE_NDR_OBJ_FILES = $(addprefix torture/ndr/, ndr.o winreg.o atsvc.o lsa.o epmap.o dfs.o netlogon.o drsuapi.o spoolss.o samr.o)

[MODULE::torture_rpc]
# TORTURE_NET and TORTURE_NBT use functions from torture_rpc...
#OUTPUT_TYPE = MERGED_OBJ
SUBSYSTEM = torture
INIT_FUNCTION = torture_rpc_init
PRIVATE_PROTO_HEADER = \
		rpc/proto.h
PRIVATE_DEPENDENCIES = \
		NDR_TABLE RPC_NDR_UNIXINFO dcerpc_samr RPC_NDR_WINREG RPC_NDR_INITSHUTDOWN \
		RPC_NDR_OXIDRESOLVER RPC_NDR_EVENTLOG RPC_NDR_ECHO RPC_NDR_SVCCTL \
		RPC_NDR_NETLOGON dcerpc_atsvc dcerpc_mgmt RPC_NDR_DRSUAPI \
		RPC_NDR_LSA RPC_NDR_EPMAPPER RPC_NDR_DFS RPC_NDR_FRSAPI RPC_NDR_SPOOLSS \
		RPC_NDR_SRVSVC RPC_NDR_WKSSVC RPC_NDR_ROT RPC_NDR_DSSETUP \
		RPC_NDR_REMACT RPC_NDR_OXIDRESOLVER WB_HELPER LIBSAMBA-NET \
		LIBCLI_AUTH POPT_CREDENTIALS TORTURE_LDAP TORTURE_UTIL TORTURE_RAP \
		dcerpc_server service process_model

torture_rpc_OBJ_FILES = $(addprefix torture/rpc/, \
		join.o lsa.o lsa_lookup.o session_key.o echo.o dfs.o drsuapi.o \
		drsuapi_cracknames.o dssync.o spoolss.o spoolss_notify.o spoolss_win.o \
		unixinfo.o samr.o samr_accessmask.o wkssvc.o srvsvc.o svcctl.o atsvc.o \
		eventlog.o epmapper.o winreg.o initshutdown.o oxidresolve.o remact.o mgmt.o \
		scanner.o autoidl.o countcalls.o testjoin.o schannel.o netlogon.o samlogon.o \
		samsync.o bind.o dssetup.o alter_context.o bench.o samba3rpc.o rpc.o async_bind.o \
		handles.o frsapi.o)

#################################
# Start SUBSYSTEM TORTURE_RAP
[MODULE::TORTURE_RAP]
SUBSYSTEM = torture
INIT_FUNCTION = torture_rap_init
PRIVATE_PROTO_HEADER = \
		rap/proto.h
PRIVATE_DEPENDENCIES = TORTURE_UTIL LIBCLI_SMB
# End SUBSYSTEM TORTURE_RAP
#################################

TORTURE_RAP_OBJ_FILES = torture/rap/rap.o

#################################
# Start SUBSYSTEM TORTURE_AUTH
[MODULE::TORTURE_AUTH]
SUBSYSTEM = torture
PRIVATE_PROTO_HEADER = \
		auth/proto.h
PRIVATE_DEPENDENCIES = \
		LIBCLI_SMB gensec auth KERBEROS \
		POPT_CREDENTIALS SMBPASSWD
# End SUBSYSTEM TORTURE_AUTH
#################################

TORTURE_AUTH_OBJ_FILES = $(addprefix torture/auth/, ntlmssp.o pac.o)

mkinclude local/config.mk

#################################
# Start MODULE TORTURE_NBENCH
[MODULE::TORTURE_NBENCH]
SUBSYSTEM = torture
INIT_FUNCTION = torture_nbench_init
PRIVATE_DEPENDENCIES = TORTURE_UTIL 
PRIVATE_PROTO_HEADER = \
		nbench/proto.h
# End MODULE TORTURE_NBENCH
#################################

TORTURE_NBENCH_OBJ_FILES = $(addprefix torture/nbench/, nbio.o nbench.o)

#################################
# Start MODULE TORTURE_UNIX
[MODULE::TORTURE_UNIX]
SUBSYSTEM = torture
INIT_FUNCTION = torture_unix_init
PRIVATE_DEPENDENCIES = TORTURE_UTIL 
PRIVATE_PROTO_HEADER = \
		unix/proto.h
# End MODULE TORTURE_UNIX
#################################

TORTURE_UNIX_OBJ_FILES = $(addprefix torture/unix/, unix.o whoami.o unix_info2.o)

#################################
# Start SUBSYSTEM TORTURE_LDAP
[MODULE::TORTURE_LDAP]
SUBSYSTEM = torture
INIT_FUNCTION = torture_ldap_init
PRIVATE_PROTO_HEADER = \
		ldap/proto.h
PRIVATE_DEPENDENCIES = \
		LIBCLI_LDAP LIBCLI_CLDAP SAMDB POPT_CREDENTIALS
# End SUBSYSTEM TORTURE_LDAP
#################################

TORTURE_LDAP_OBJ_FILES = $(addprefix torture/ldap/, common.o basic.o schema.o uptodatevector.o cldap.o cldapbench.o)


#################################
# Start SUBSYSTEM TORTURE_NBT
[MODULE::TORTURE_NBT]
SUBSYSTEM = torture
INIT_FUNCTION = torture_nbt_init
PRIVATE_PROTO_HEADER = \
		nbt/proto.h
PRIVATE_DEPENDENCIES = \
		LIBCLI_SMB LIBCLI_NBT LIBCLI_DGRAM LIBCLI_WREPL torture_rpc
# End SUBSYSTEM TORTURE_NBT
#################################

TORTURE_NBT_OBJ_FILES = $(addprefix torture/nbt/, query.o register.o \
	wins.o winsbench.o winsreplication.o dgram.o nbt.o)


#################################
# Start SUBSYSTEM TORTURE_NET
[MODULE::TORTURE_NET]
SUBSYSTEM = torture
INIT_FUNCTION = torture_net_init
PRIVATE_PROTO_HEADER = \
		libnet/proto.h
PRIVATE_DEPENDENCIES = \
		LIBSAMBA-NET \
		POPT_CREDENTIALS \
		torture_rpc
# End SUBSYSTEM TORTURE_NET
#################################

TORTURE_NET_OBJ_FILES = $(addprefix torture/libnet/, libnet.o \
					   utils.o userinfo.o userman.o groupinfo.o groupman.o \
					   domain.o libnet_lookup.o libnet_user.o libnet_group.o \
					   libnet_share.o libnet_rpc.o libnet_domain.o libnet_BecomeDC.o)


#################################
# Start BINARY smbtorture
[BINARY::smbtorture]
INSTALLDIR = BINDIR
PRIVATE_DEPENDENCIES = \
		torture \
		LIBPOPT \
		POPT_SAMBA \
		POPT_CREDENTIALS \
		dcerpc \
		LIBCLI_SMB \
		SMBREADLINE
# End BINARY smbtorture
#################################

smbtorture_OBJ_FILES = torture/smbtorture.o

MANPAGES += torture/man/smbtorture.1

#################################
# Start BINARY gentest
[BINARY::gentest]
INSTALLDIR = BINDIR
PRIVATE_DEPENDENCIES = \
		LIBSAMBA-CONFIG \
		LIBSAMBA-UTIL \
		LIBPOPT \
		POPT_SAMBA \
		POPT_CREDENTIALS \
		LIBCLI_SMB \
		LIBCLI_RAW
# End BINARY gentest
#################################

gentest_OBJ_FILES = torture/gentest.o

MANPAGES += torture/man/gentest.1

#################################
# Start BINARY masktest
[BINARY::masktest]
INSTALLDIR = BINDIR
PRIVATE_DEPENDENCIES = \
		LIBSAMBA-CONFIG \
		LIBSAMBA-UTIL \
		LIBPOPT \
		POPT_SAMBA \
		POPT_CREDENTIALS \
		LIBCLI_SMB
# End BINARY masktest
#################################

masktest_OBJ_FILES = torture/masktest.o

MANPAGES += torture/man/masktest.1

#################################
# Start BINARY locktest
[BINARY::locktest]
INSTALLDIR = BINDIR
PRIVATE_DEPENDENCIES = \
		LIBPOPT \
		POPT_SAMBA \
		POPT_CREDENTIALS \
		LIBSAMBA-UTIL \
		LIBCLI_SMB \
		LIBSAMBA-CONFIG
# End BINARY locktest
#################################

locktest_OBJ_FILES = torture/locktest.o

MANPAGES += torture/man/locktest.1

COV_TARGET = test

COV_VARS = \
	CFLAGS="$(CFLAGS) --coverage" \
	LDFLAGS="$(LDFLAGS) --coverage"

test_cov:
	-$(MAKE) $(COV_TARGET) $(COV_VARS)

gcov: test_cov
	for I in $(sort $(dir $(ALL_OBJS))); \
		do $(GCOV) -p -o $$I $$I/*.c; \
	done

lcov-split: 
	rm -f samba.info
	@$(MAKE) $(COV_TARGET) $(COV_VARS) \
		TEST_OPTIONS="--analyse-cmd=\"lcov --base-directory `pwd` --directory . --capture --output-file samba.info -t\""
	-rm heimdal/lib/*/{lex,parse}.{gcda,gcno}
	-rm lib/policy/*/{lex,parse}.{gcda,gcno}
	genhtml -o coverage samba.info

lcov: test_cov
	-rm heimdal/lib/*/{lex,parse}.{gcda,gcno}
	-rm lib/policy/*/{lex,parse}.{gcda,gcno}
	lcov --base-directory `pwd` --directory . --capture --output-file samba.info
	genhtml -o coverage samba.info

testcov-html:: lcov
