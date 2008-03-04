################################################
# Start SUBSYSTEM LIBNDR
[LIBRARY::LIBNDR]
VERSION = 0.0.1
SO_VERSION = 0
PC_FILE = ndr.pc
PRIVATE_PROTO_HEADER = ndr/libndr_proto.h
PUBLIC_DEPENDENCIES = LIBSAMBA-ERRORS LIBTALLOC LIBSAMBA-UTIL CHARSET EXT_NSL \
					  LIBSAMBA-CONFIG

LIBNDR_OBJ_FILES = $(addprefix librpc/ndr/, ndr.o ndr_basic.o ndr_string.o uuid.o)

# End SUBSYSTEM LIBNDR
################################################

PUBLIC_HEADERS += librpc/ndr/libndr.h

#################################
# Start BINARY ndrdump
[BINARY::ndrdump]
INSTALLDIR = BINDIR
PRIVATE_DEPENDENCIES = \
		LIBSAMBA-CONFIG \
		LIBSAMBA-UTIL \
		LIBPOPT \
		POPT_SAMBA \
		NDR_TABLE \
		LIBSAMBA-ERRORS
# FIXME: ndrdump shouldn't have to depend on RPC...
# End BINARY ndrdump
#################################

ndrdump_OBJ_FILES = librpc/tools/ndrdump.o

MANPAGES += librpc/tools/ndrdump.1

################################################
# Start SUBSYSTEM NDR_COMPRESSION
[SUBSYSTEM::NDR_COMPRESSION]
PRIVATE_PROTO_HEADER = ndr/ndr_compression.h
PUBLIC_DEPENDENCIES = LIBCOMPRESSION LIBSAMBA-ERRORS LIBNDR
# End SUBSYSTEM NDR_COMPRESSION
################################################

NDR_COMPRESSION_OBJ_FILES = librpc/ndr/ndr_compression.o

[SUBSYSTEM::NDR_SECURITY]
PUBLIC_DEPENDENCIES = NDR_MISC LIBSECURITY

NDR_SECURITY_OBJ_FILES = librpc/gen_ndr/ndr_security.o librpc/ndr/ndr_sec_helper.o 

PUBLIC_HEADERS += librpc/gen_ndr/security.h

[SUBSYSTEM::NDR_AUDIOSRV]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_AUDIOSRV_OBJ_FILES = librpc/gen_ndr/ndr_audiosrv.o

[SUBSYSTEM::NDR_DNSSERVER]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_DNSSERVER_OBJ_FILES = librpc/gen_ndr/ndr_dnsserver.o

[SUBSYSTEM::NDR_WINSTATION]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_WINSTATION_OBJ_FILES = librpc/gen_ndr/ndr_winstation.o

[SUBSYSTEM::NDR_ECHO]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_ECHO_OBJ_FILES = librpc/gen_ndr/ndr_echo.o

[SUBSYSTEM::NDR_IRPC]
PUBLIC_DEPENDENCIES = LIBNDR NDR_SECURITY NDR_NBT

NDR_IRPC_OBJ_FILES = librpc/gen_ndr/ndr_irpc.o

[SUBSYSTEM::NDR_DSBACKUP]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_DSBACKUP_OBJ_FILES = librpc/gen_ndr/ndr_dsbackup.o

[SUBSYSTEM::NDR_EFS]
PUBLIC_DEPENDENCIES = LIBNDR NDR_SECURITY

NDR_EFS_OBJ_FILES = librpc/gen_ndr/ndr_efs.o

[SUBSYSTEM::NDR_MISC]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_MISC_OBJ_FILES = librpc/gen_ndr/ndr_misc.o librpc/ndr/ndr_misc.o

PUBLIC_HEADERS += librpc/gen_ndr/misc.h librpc/gen_ndr/ndr_misc.h

[SUBSYSTEM::NDR_ROT]
PUBLIC_DEPENDENCIES = LIBNDR NDR_ORPC

NDR_ROT_OBJ_FILES = librpc/gen_ndr/ndr_rot.o

[SUBSYSTEM::NDR_LSA]
PUBLIC_DEPENDENCIES = LIBNDR NDR_SECURITY

NDR_LSA_OBJ_FILES = librpc/gen_ndr/ndr_lsa.o

PUBLIC_HEADERS += librpc/gen_ndr/lsa.h

[SUBSYSTEM::NDR_DFS]
PUBLIC_DEPENDENCIES = LIBNDR NDR_MISC

NDR_DFS_OJB_LIST = librpc/gen_ndr/ndr_dfs.o

[SUBSYSTEM::NDR_FRSRPC]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_FRSRPC_OBJ_FILES = librpc/gen_ndr/ndr_frsrpc.o

[SUBSYSTEM::NDR_FRSAPI]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_FRSAPI_OBJ_FILES = librpc/gen_ndr/ndr_frsapi.o

[SUBSYSTEM::NDR_DRSUAPI]
PUBLIC_DEPENDENCIES = LIBNDR NDR_COMPRESSION NDR_SECURITY NDR_SAMR ASN1_UTIL

NDR_DRSUAPI_OBJ_FILES = librpc/gen_ndr/ndr_drsuapi.o librpc/ndr/ndr_drsuapi.o

[SUBSYSTEM::NDR_DRSBLOBS]
PUBLIC_DEPENDENCIES = LIBNDR NDR_MISC NDR_DRSUAPI

NDR_DRSBLOBS_OBJ_FILES = librpc/gen_ndr/ndr_drsblobs.o

[SUBSYSTEM::NDR_SASL_HELPERS]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_SASL_HELPERS_OBJ_FILES = librpc/gen_ndr/ndr_sasl_helpers.o

[SUBSYSTEM::NDR_POLICYAGENT]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_POLICYAGENT_OBJ_FILES = librpc/gen_ndr/ndr_policyagent.o

[SUBSYSTEM::NDR_UNIXINFO]
PUBLIC_DEPENDENCIES = LIBNDR NDR_SECURITY

NDR_UNIXINFO_OBJ_FILES = librpc/gen_ndr/ndr_unixinfo.o

[SUBSYSTEM::NDR_SAMR]
PUBLIC_DEPENDENCIES = LIBNDR NDR_MISC NDR_LSA NDR_SECURITY

NDR_SAMR_OBJ_FILES = librpc/gen_ndr/ndr_samr.o

PUBLIC_HEADERS += $(addprefix librpc/, gen_ndr/samr.h gen_ndr/ndr_samr.h gen_ndr/ndr_samr_c.h)

[SUBSYSTEM::NDR_NFS4ACL]
PUBLIC_DEPENDENCIES = LIBNDR NDR_MISC NDR_SECURITY

NDR_NFS4ACL_OBJ_FILES = librpc/gen_ndr/ndr_nfs4acl.o

[SUBSYSTEM::NDR_SPOOLSS]
PUBLIC_DEPENDENCIES = LIBNDR NDR_SPOOLSS_BUF NDR_SECURITY

NDR_SPOOLSS_OBJ_FILES = librpc/gen_ndr/ndr_spoolss.o

[SUBSYSTEM::NDR_SPOOLSS_BUF]
PRIVATE_PROTO_HEADER = ndr/ndr_spoolss_buf.h

NDR_SPOOLSS_BUF_OBJ_FILES = librpc/ndr/ndr_spoolss_buf.o

[SUBSYSTEM::NDR_WKSSVC]
PUBLIC_DEPENDENCIES = LIBNDR NDR_SRVSVC NDR_MISC NDR_SECURITY

NDR_WKSSVC_OBJ_FILES = librpc/gen_ndr/ndr_wkssvc.o

[SUBSYSTEM::NDR_SRVSVC]
PUBLIC_DEPENDENCIES = LIBNDR NDR_SVCCTL NDR_SECURITY

NDR_SRVSVC_OBJ_FILES = librpc/gen_ndr/ndr_srvsvc.o

[SUBSYSTEM::NDR_SVCCTL]
PUBLIC_DEPENDENCIES = LIBNDR NDR_MISC

NDR_SVCCTL_OBJ_FILES = librpc/gen_ndr/ndr_svcctl.o

PUBLIC_HEADERS += $(addprefix librpc/, gen_ndr/ndr_svcctl.h gen_ndr/svcctl.h)

[SUBSYSTEM::NDR_ATSVC]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_ATSVC_OBJ_FILES = librpc/gen_ndr/ndr_atsvc.o

PUBLIC_HEADERS += $(addprefix librpc/, gen_ndr/atsvc.h gen_ndr/ndr_atsvc.h)

[SUBSYSTEM::NDR_EVENTLOG]
PUBLIC_DEPENDENCIES = LIBNDR NDR_LSA

NDR_EVENTLOG_OBJ_FILES = librpc/gen_ndr/ndr_eventlog.o

[SUBSYSTEM::NDR_EPMAPPER]
PUBLIC_DEPENDENCIES = LIBNDR NDR_MISC

NDR_EPMAPPER_OBJ_FILES = librpc/gen_ndr/ndr_epmapper.o

[SUBSYSTEM::NDR_DBGIDL]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_DBGIDL_OBJ_FILES = librpc/gen_ndr/ndr_dbgidl.o

[SUBSYSTEM::NDR_DSSETUP]
PUBLIC_DEPENDENCIES = LIBNDR NDR_MISC

NDR_DSSETUP_OBJ_FILES = librpc/gen_ndr/ndr_dssetup.o

[SUBSYSTEM::NDR_MSGSVC]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_MSGSVC_OBJ_FILES = librpc/gen_ndr/ndr_msgsvc.o

[SUBSYSTEM::NDR_WINS]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_WINS_OBJ_FILES = librpc/gen_ndr/ndr_wins.o

[SUBSYSTEM::NDR_WINREG]
PUBLIC_DEPENDENCIES = LIBNDR NDR_INITSHUTDOWN NDR_SECURITY NDR_MISC

NDR_WINREG_OBJ_FILES = librpc/gen_ndr/ndr_winreg.o

[SUBSYSTEM::NDR_INITSHUTDOWN]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_INITSHUTDOWN_OBJ_FILES = librpc/gen_ndr/ndr_initshutdown.o

[SUBSYSTEM::NDR_MGMT]
PUBLIC_DEPENDENCIES = LIBNDR 

NDR_MGMT_OBJ_FILES = librpc/gen_ndr/ndr_mgmt.o

[SUBSYSTEM::NDR_PROTECTED_STORAGE]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_PROTECTED_STORAGE_OBJ_FILES = librpc/gen_ndr/ndr_protected_storage.o

[SUBSYSTEM::NDR_ORPC]
PUBLIC_DEPENDENCIES = LIBNDR 

NDR_ORPC_OBJ_FILES = librpc/gen_ndr/ndr_orpc.o librpc/ndr/ndr_orpc.o 

[SUBSYSTEM::NDR_OXIDRESOLVER]
PUBLIC_DEPENDENCIES = LIBNDR NDR_ORPC NDR_MISC

NDR_OXIDRESOLVER_OBJ_FILES = librpc/gen_ndr/ndr_oxidresolver.o

[SUBSYSTEM::NDR_REMACT]
PUBLIC_DEPENDENCIES = LIBNDR NDR_ORPC NDR_MISC

NDR_REMACT_OBJ_FILES = librpc/gen_ndr/ndr_remact.o

[SUBSYSTEM::NDR_WZCSVC]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_WZCSVC_OBJ_FILES = librpc/gen_ndr/ndr_wzcsvc.o

[SUBSYSTEM::NDR_BROWSER]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_BROWSER_OBJ_FILES = librpc/gen_ndr/ndr_browser.o

[SUBSYSTEM::NDR_W32TIME]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_W32TIME_OBJ_FILES = librpc/gen_ndr/ndr_w32time.o

[SUBSYSTEM::NDR_SCERPC]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_SCERPC_OBJ_FILES = librpc/gen_ndr/ndr_scerpc.o

[SUBSYSTEM::NDR_NTSVCS]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_NTSVCS_OBJ_FILES = librpc/gen_ndr/ndr_ntsvcs.o

[SUBSYSTEM::NDR_NETLOGON]
PUBLIC_DEPENDENCIES = LIBNDR NDR_SAMR NDR_LSA NDR_SECURITY

NDR_NETLOGON_OBJ_FILES = librpc/gen_ndr/ndr_netlogon.o

PUBLIC_HEADERS += $(addprefix librpc/, gen_ndr/netlogon.h)

[SUBSYSTEM::NDR_TRKWKS]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_TRKWKS_OBJ_FILES = librpc/gen_ndr/ndr_trkwks.o

[SUBSYSTEM::NDR_KEYSVC]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_KEYSVC_OBJ_FILES = librpc/gen_ndr/ndr_keysvc.o

[SUBSYSTEM::NDR_KRB5PAC]
PUBLIC_DEPENDENCIES = LIBNDR NDR_NETLOGON NDR_SECURITY

NDR_KRB5PAC_OBJ_FILES = librpc/gen_ndr/ndr_krb5pac.o librpc/ndr/ndr_krb5pac.o

[SUBSYSTEM::NDR_XATTR]
PUBLIC_DEPENDENCIES = LIBNDR NDR_SECURITY

NDR_XATTR_OBJ_FILES = librpc/gen_ndr/ndr_xattr.o

[SUBSYSTEM::NDR_OPENDB]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_OPENDB_OBJ_FILES = librpc/gen_ndr/ndr_opendb.o

[SUBSYSTEM::NDR_NOTIFY]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_NOTIFY_OBJ_FILES = librpc/gen_ndr/ndr_notify.o

[SUBSYSTEM::NDR_SCHANNEL]
PUBLIC_DEPENDENCIES = LIBNDR NDR_NBT

NDR_SCHANNEL_OBJ_FILES = librpc/gen_ndr/ndr_schannel.o

[SUBSYSTEM::NDR_NBT]
PUBLIC_DEPENDENCIES = LIBNDR NDR_MISC NDR_NBT_BUF NDR_SVCCTL NDR_SECURITY

NDR_NBT_OBJ_FILES = librpc/gen_ndr/ndr_nbt.o

PUBLIC_HEADERS += librpc/gen_ndr/nbt.h

[SUBSYSTEM::NDR_WINSREPL]
PUBLIC_DEPENDENCIES = LIBNDR NDR_NBT

NDR_WINSREPL_OBJ_FILES = librpc/gen_ndr/ndr_winsrepl.o

[SUBSYSTEM::NDR_WINBIND]
PUBLIC_DEPENDENCIES = LIBNDR NDR_NETLOGON

NDR_WINBIND_OBJ_FILES = librpc/gen_ndr/ndr_winbind.o
PUBLIC_HEADERS += librpc/gen_ndr/winbind.h

librpc/idl-deps:
	./librpc/idl-deps.pl librpc/idl/*.idl >$@

clean:: 
	rm -f librpc/idl-deps

include librpc/idl-deps

librpc/gen_ndr/tables.c: $(IDL_NDR_PARSE_H_FILES)
	@echo Generating $@
	@$(PERL) $(srcdir)/librpc/tables.pl --output=$@ $^ > librpc/gen_ndr/tables.x
	@mv librpc/gen_ndr/tables.x $@

[SUBSYSTEM::NDR_TABLE]
PRIVATE_PROTO_HEADER = ndr/ndr_table.h
PUBLIC_DEPENDENCIES = \
	NDR_AUDIOSRV NDR_ECHO NDR_DCERPC \
	NDR_DSBACKUP NDR_EFS NDR_MISC NDR_LSA NDR_DFS NDR_DRSUAPI \
	NDR_POLICYAGENT NDR_UNIXINFO NDR_SAMR NDR_SPOOLSS NDR_WKSSVC NDR_SRVSVC NDR_ATSVC \
	NDR_EVENTLOG NDR_EPMAPPER NDR_DBGIDL NDR_DSSETUP NDR_MSGSVC NDR_WINS \
	NDR_WINREG NDR_MGMT NDR_PROTECTED_STORAGE NDR_OXIDRESOLVER \
	NDR_REMACT NDR_WZCSVC NDR_BROWSER NDR_W32TIME NDR_SCERPC NDR_NTSVCS \
	NDR_NETLOGON NDR_TRKWKS NDR_KEYSVC NDR_KRB5PAC NDR_XATTR NDR_SCHANNEL \
	NDR_ROT NDR_DRSBLOBS NDR_SVCCTL NDR_NBT NDR_WINSREPL NDR_SECURITY \
	NDR_INITSHUTDOWN NDR_DNSSERVER NDR_WINSTATION NDR_IRPC NDR_OPENDB \
	NDR_SASL_HELPERS NDR_NOTIFY NDR_WINBIND NDR_FRSRPC NDR_FRSAPI NDR_NFS4ACL

NDR_TABLE_OBJ_FILES = librpc/ndr/ndr_table.o librpc/gen_ndr/tables.o

[SUBSYSTEM::RPC_NDR_ROT]
PUBLIC_DEPENDENCIES = NDR_ROT dcerpc

RPC_NDR_ROT_OBJ_FILES = librpc/gen_ndr/ndr_rot_c.o

[SUBSYSTEM::RPC_NDR_AUDIOSRV]
PUBLIC_DEPENDENCIES = NDR_AUDIOSRV dcerpc

RPC_NDR_AUDIOSRV_OBJ_FILES = librpc/gen_ndr/ndr_audiosrv_c.o

[SUBSYSTEM::RPC_NDR_ECHO]
PUBLIC_DEPENDENCIES = dcerpc NDR_ECHO

RPC_NDR_ECHO_OBJ_FILES = librpc/gen_ndr/ndr_echo_c.o

[SUBSYSTEM::RPC_NDR_DSBACKUP]
PUBLIC_DEPENDENCIES = dcerpc NDR_DSBACKUP

RPC_NDR_DSBACKUP_OBJ_FILES = librpc/gen_ndr/ndr_dsbackup_c.o

[SUBSYSTEM::RPC_NDR_EFS]
PUBLIC_DEPENDENCIES = dcerpc NDR_EFS

RPC_NDR_EFS_OBJ_FILES = librpc/gen_ndr/ndr_efs_c.o

[SUBSYSTEM::RPC_NDR_LSA]
PUBLIC_DEPENDENCIES = dcerpc NDR_LSA

RPC_NDR_LSA_OBJ_FILES = librpc/gen_ndr/ndr_lsa_c.o

[SUBSYSTEM::RPC_NDR_DFS]
PUBLIC_DEPENDENCIES = dcerpc NDR_DFS

RPC_NDR_DFS_OBJ_FILES = librpc/gen_ndr/ndr_dfs_c.o

[SUBSYSTEM::RPC_NDR_FRSAPI]
PUBLIC_DEPENDENCIES = dcerpc NDR_FRSAPI

RPC_NDR_FRSAPI_OBJ_FILES = librpc/gen_ndr/ndr_frsapi_c.o

[SUBSYSTEM::RPC_NDR_DRSUAPI]
PUBLIC_DEPENDENCIES = dcerpc NDR_DRSUAPI

RPC_NDR_DRSUAPI_OBJ_FILES = librpc/gen_ndr/ndr_drsuapi_c.o

[SUBSYSTEM::RPC_NDR_POLICYAGENT]
PUBLIC_DEPENDENCIES = dcerpc NDR_POLICYAGENT

RPC_NDR_POLICYAGENT_OBJ_FILES = librpc/gen_ndr/ndr_policyagent_c.o

[SUBSYSTEM::RPC_NDR_UNIXINFO]
PUBLIC_DEPENDENCIES = dcerpc NDR_UNIXINFO

RPC_NDR_UNIXINFO_OBJ_FILES = librpc/gen_ndr/ndr_unixinfo_c.o

[LIBRARY::dcerpc_samr]
PC_FILE = dcerpc_samr.pc
PUBLIC_DEPENDENCIES = dcerpc NDR_SAMR 
VERSION = 0.0.1
SO_VERSION = 0

dcerpc_samr_OBJ_FILES = librpc/gen_ndr/ndr_samr_c.o

[SUBSYSTEM::RPC_NDR_SPOOLSS]
PUBLIC_DEPENDENCIES = dcerpc NDR_SPOOLSS

RPC_NDR_SPOOLSS_OBJ_FILES = librpc/gen_ndr/ndr_spoolss_c.o

[SUBSYSTEM::RPC_NDR_WKSSVC]
PUBLIC_DEPENDENCIES = dcerpc NDR_WKSSVC

RPC_NDR_WKSSVC_OBJ_FILES = librpc/gen_ndr/ndr_wkssvc_c.o

[SUBSYSTEM::RPC_NDR_SRVSVC]
PUBLIC_DEPENDENCIES = dcerpc NDR_SRVSVC

RPC_NDR_SRVSVC_OBJ_FILES = librpc/gen_ndr/ndr_srvsvc_c.o

[SUBSYSTEM::RPC_NDR_SVCCTL]
PUBLIC_DEPENDENCIES = dcerpc NDR_SVCCTL

RPC_NDR_SVCCTL_OBJ_FILES = librpc/gen_ndr/ndr_svcctl_c.o

PUBLIC_HEADERS += librpc/gen_ndr/ndr_svcctl_c.h

[SUBSYSTEM::dcerpc_atsvc]
PUBLIC_DEPENDENCIES = dcerpc NDR_ATSVC

dcerpc_atsvc_OBJ_FILES = librpc/gen_ndr/ndr_atsvc_c.o

PUBLIC_HEADERS += librpc/gen_ndr/ndr_atsvc_c.h

[SUBSYSTEM::RPC_NDR_EVENTLOG]
PUBLIC_DEPENDENCIES = dcerpc NDR_EVENTLOG

RPC_NDR_EVENTLOG_OBJ_FILES = librpc/gen_ndr/ndr_eventlog_c.o

[SUBSYSTEM::RPC_NDR_EPMAPPER]
PUBLIC_DEPENDENCIES = NDR_EPMAPPER 

RPC_NDR_EPMAPPER_OBJ_FILES = librpc/gen_ndr/ndr_epmapper_c.o

[SUBSYSTEM::RPC_NDR_DBGIDL]
PUBLIC_DEPENDENCIES = dcerpc NDR_DBGIDL

RPC_NDR_DBGIDL_OBJ_FILES = librpc/gen_ndr/ndr_dbgidl_c.o

[SUBSYSTEM::RPC_NDR_DSSETUP]
PUBLIC_DEPENDENCIES = dcerpc NDR_DSSETUP

RPC_NDR_DSSETUP_OBJ_FILES = librpc/gen_ndr/ndr_dssetup_c.o

[SUBSYSTEM::RPC_NDR_MSGSVC]
PUBLIC_DEPENDENCIES = dcerpc NDR_MSGSVC

RPC_NDR_MSGSVC_OBJ_FILES = librpc/gen_ndr/ndr_msgsvc_c.o

[SUBSYSTEM::RPC_NDR_WINS]
PUBLIC_DEPENDENCIES = dcerpc NDR_WINS

RPC_NDR_WINS_OBJ_FILES = librpc/gen_ndr/ndr_wins_c.o

[SUBSYSTEM::RPC_NDR_WINREG]
PUBLIC_DEPENDENCIES = dcerpc NDR_WINREG

RPC_NDR_WINREG_OBJ_FILES = librpc/gen_ndr/ndr_winreg_c.o

[SUBSYSTEM::RPC_NDR_INITSHUTDOWN]
PUBLIC_DEPENDENCIES = dcerpc NDR_INITSHUTDOWN

RPC_NDR_INITSHUTDOWN_OBJ_FILES = librpc/gen_ndr/ndr_initshutdown_c.o

[SUBSYSTEM::dcerpc_mgmt]
PRIVATE_DEPENDENCIES = NDR_MGMT

dcerpc_mgmt_OBJ_FILES = librpc/gen_ndr/ndr_mgmt_c.o

[SUBSYSTEM::RPC_NDR_PROTECTED_STORAGE]
PUBLIC_DEPENDENCIES = dcerpc NDR_PROTECTED_STORAGE

RPC_NDR_PROTECTED_STORAGE_OBJ_FILES = librpc/gen_ndr/ndr_protected_storage_c.o

[SUBSYSTEM::RPC_NDR_OXIDRESOLVER]
PUBLIC_DEPENDENCIES = dcerpc NDR_OXIDRESOLVER

RPC_NDR_OXIDRESOLVER_OBJ_FILES = librpc/gen_ndr/ndr_oxidresolver_c.o

[SUBSYSTEM::RPC_NDR_REMACT]
PUBLIC_DEPENDENCIES = dcerpc NDR_REMACT

RPC_NDR_REMACT_OBJ_FILES = librpc/gen_ndr/ndr_remact_c.o

[SUBSYSTEM::RPC_NDR_WZCSVC]
PUBLIC_DEPENDENCIES = dcerpc NDR_WZCSVC

RPC_NDR_WZCSVC_OBJ_FILES = librpc/gen_ndr/ndr_wzcsvc_c.o

[SUBSYSTEM::RPC_NDR_W32TIME]
PUBLIC_DEPENDENCIES = dcerpc NDR_W32TIME

RPC_NDR_W32TIME_OBJ_FILES = librpc/gen_ndr/ndr_w32time_c.o

[SUBSYSTEM::RPC_NDR_SCERPC]
PUBLIC_DEPENDENCIES = dcerpc NDR_SCERPC

RPC_NDR_SCERPC_OBJ_FILES = librpc/gen_ndr/ndr_scerpc_c.o

[SUBSYSTEM::RPC_NDR_NTSVCS]
PUBLIC_DEPENDENCIES = dcerpc NDR_NTSVCS

RPC_NDR_NTSVCS_OBJ_FILES = librpc/gen_ndr/ndr_ntsvcs_c.o

[SUBSYSTEM::RPC_NDR_NETLOGON]
PUBLIC_DEPENDENCIES = NDR_NETLOGON

RPC_NDR_NETLOGON_OBJ_FILES = librpc/gen_ndr/ndr_netlogon_c.o

[SUBSYSTEM::RPC_NDR_TRKWKS]
PUBLIC_DEPENDENCIES = dcerpc NDR_TRKWKS

RPC_NDR_TRKWKS_OBJ_FILES = librpc/gen_ndr/ndr_trkwks_c.o

[SUBSYSTEM::RPC_NDR_KEYSVC]
PUBLIC_DEPENDENCIES = dcerpc NDR_KEYSVC

RPC_NDR_KEYSVC_OBJ_FILES = librpc/gen_ndr/ndr_keysvc_c.o

[SUBSYSTEM::NDR_DCERPC]
PUBLIC_DEPENDENCIES = LIBNDR NDR_MISC

NDR_DCERPC_OBJ_FILES = librpc/gen_ndr/ndr_dcerpc.o

PUBLIC_HEADERS += $(addprefix librpc/, gen_ndr/dcerpc.h gen_ndr/ndr_dcerpc.h)

################################################
# Start SUBSYSTEM dcerpc
[LIBRARY::dcerpc]
VERSION = 0.0.1
SO_VERSION = 0
PC_FILE = dcerpc.pc
PRIVATE_PROTO_HEADER = rpc/dcerpc_proto.h
PRIVATE_DEPENDENCIES = \
		samba-socket LIBCLI_RESOLVE LIBCLI_SMB LIBCLI_SMB2 \
		LIBNDR NDR_DCERPC RPC_NDR_EPMAPPER \
		NDR_SCHANNEL RPC_NDR_NETLOGON \
		gensec LIBCLI_AUTH LIBCLI_RAW \
		LP_RESOLVE
PUBLIC_DEPENDENCIES = CREDENTIALS 
# End SUBSYSTEM dcerpc
################################################

dcerpc_OBJ_FILES = $(addprefix librpc/rpc/, dcerpc.o dcerpc_auth.o dcerpc_schannel.o dcerpc_util.o \
				  dcerpc_error.o dcerpc_smb.o dcerpc_smb2.o dcerpc_sock.o dcerpc_connect.o dcerpc_secondary.o)


PUBLIC_HEADERS += $(addprefix librpc/, rpc/dcerpc.h \
			gen_ndr/mgmt.h gen_ndr/ndr_mgmt.h gen_ndr/ndr_mgmt_c.h \
			gen_ndr/epmapper.h gen_ndr/ndr_epmapper.h gen_ndr/ndr_epmapper_c.h)


[MODULE::RPC_EJS_ECHO]
INIT_FUNCTION = ejs_init_rpcecho
SUBSYSTEM = smbcalls
PRIVATE_DEPENDENCIES = dcerpc NDR_ECHO EJSRPC

RPC_EJS_ECHO_OBJ_FILES = librpc/gen_ndr/ndr_echo_ejs.o

[MODULE::RPC_EJS_MISC]
INIT_FUNCTION = ejs_init_misc
SUBSYSTEM = smbcalls
PRIVATE_DEPENDENCIES = dcerpc NDR_MISC EJSRPC

RPC_EJS_MISC_OBJ_FILES = librpc/gen_ndr/ndr_misc_ejs.o

[MODULE::RPC_EJS_SAMR]
INIT_FUNCTION = ejs_init_samr
SUBSYSTEM = smbcalls
PRIVATE_DEPENDENCIES = dcerpc NDR_SAMR EJSRPC RPC_EJS_LSA RPC_EJS_SECURITY RPC_EJS_MISC

RPC_EJS_SAMR_OBJ_FILES = librpc/gen_ndr/ndr_samr_ejs.o

[MODULE::RPC_EJS_SECURITY]
INIT_FUNCTION = ejs_init_security
SUBSYSTEM = smbcalls
PRIVATE_DEPENDENCIES = dcerpc NDR_SECURITY EJSRPC

RPC_EJS_SECURITY_OBJ_FILES = librpc/gen_ndr/ndr_security_ejs.o

[MODULE::RPC_EJS_LSA]
INIT_FUNCTION = ejs_init_lsarpc
SUBSYSTEM = smbcalls
PRIVATE_DEPENDENCIES = dcerpc NDR_LSA EJSRPC RPC_EJS_SECURITY RPC_EJS_MISC

RPC_EJS_LSA_OBJ_FILES = librpc/gen_ndr/ndr_lsa_ejs.o

[MODULE::RPC_EJS_DFS]
INIT_FUNCTION = ejs_init_netdfs
SUBSYSTEM = smbcalls
PRIVATE_DEPENDENCIES = dcerpc NDR_DFS EJSRPC

RPC_EJS_DFS_OBJ_FILES = librpc/gen_ndr/ndr_dfs_ejs.o

[MODULE::RPC_EJS_DRSUAPI]
INIT_FUNCTION = ejs_init_drsuapi
SUBSYSTEM = smbcalls
PRIVATE_DEPENDENCIES = dcerpc NDR_DRSUAPI EJSRPC RPC_EJS_MISC RPC_EJS_SAMR

RPC_EJS_DRSUAPI_OBJ_FILES = librpc/gen_ndr/ndr_drsuapi_ejs.o

[MODULE::RPC_EJS_SPOOLSS]
INIT_FUNCTION = ejs_init_spoolss
SUBSYSTEM = smbcalls
ENABLE = NO
PRIVATE_DEPENDENCIES = dcerpc NDR_SPOOLSS EJSRPC

RPC_EJS_SPOOLSS_OBJ_FILES = librpc/gen_ndr/ndr_spoolss_ejs.o

[MODULE::RPC_EJS_WKSSVC]
INIT_FUNCTION = ejs_init_wkssvc
SUBSYSTEM = smbcalls
PRIVATE_DEPENDENCIES = dcerpc NDR_WKSSVC EJSRPC RPC_EJS_SRVSVC RPC_EJS_MISC

RPC_EJS_WKSSVC_OBJ_FILES = librpc/gen_ndr/ndr_wkssvc_ejs.o

[MODULE::RPC_EJS_SRVSVC]
INIT_FUNCTION = ejs_init_srvsvc
SUBSYSTEM = smbcalls
PRIVATE_DEPENDENCIES = dcerpc NDR_SRVSVC EJSRPC RPC_EJS_MISC RPC_EJS_SVCCTL RPC_EJS_SECURITY

RPC_EJS_SRVSVC_OBJ_FILES = librpc/gen_ndr/ndr_srvsvc_ejs.o

[MODULE::RPC_EJS_EVENTLOG]
INIT_FUNCTION = ejs_init_eventlog
SUBSYSTEM = smbcalls
PRIVATE_DEPENDENCIES = dcerpc NDR_EVENTLOG EJSRPC RPC_EJS_MISC

RPC_EJS_EVENTLOG_OBJ_FILES = librpc/gen_ndr/ndr_eventlog_ejs.o

[MODULE::RPC_EJS_WINREG]
INIT_FUNCTION = ejs_init_winreg
SUBSYSTEM = smbcalls
PRIVATE_DEPENDENCIES = dcerpc NDR_WINREG EJSRPC RPC_EJS_INITSHUTDOWN \
					  RPC_EJS_MISC RPC_EJS_SECURITY

RPC_EJS_WINREG_OBJ_FILES = librpc/gen_ndr/ndr_winreg_ejs.o

[MODULE::RPC_EJS_INITSHUTDOWN]
INIT_FUNCTION = ejs_init_initshutdown
SUBSYSTEM = smbcalls
PRIVATE_DEPENDENCIES = dcerpc NDR_INITSHUTDOWN EJSRPC

RPC_EJS_INITSHUTDOWN_OBJ_FILES = librpc/gen_ndr/ndr_initshutdown_ejs.o

[MODULE::RPC_EJS_NETLOGON]
INIT_FUNCTION = ejs_init_netlogon
SUBSYSTEM = smbcalls
PRIVATE_DEPENDENCIES = dcerpc NDR_NETLOGON EJSRPC RPC_EJS_SAMR RPC_EJS_SECURITY RPC_EJS_MISC

RPC_EJS_NETLOGON_OBJ_FILES = librpc/gen_ndr/ndr_netlogon_ejs.o

[MODULE::RPC_EJS_SVCCTL]
INIT_FUNCTION = ejs_init_svcctl
SUBSYSTEM = smbcalls
PRIVATE_DEPENDENCIES = dcerpc NDR_SVCCTL EJSRPC RPC_EJS_MISC

RPC_EJS_SVCCTL_OBJ_FILES = librpc/gen_ndr/ndr_svcctl_ejs.o

[MODULE::RPC_EJS_IRPC]
INIT_FUNCTION = ejs_init_irpc
SUBSYSTEM = smbcalls
PRIVATE_DEPENDENCIES = dcerpc NDR_IRPC EJSRPC

RPC_EJS_IRPC_OBJ_FILES = librpc/gen_ndr/ndr_irpc_ejs.o

[PYTHON::swig_dcerpc]
SWIG_FILE = rpc/dcerpc.i
PUBLIC_DEPENDENCIES = LIBCLI_SMB NDR_MISC LIBSAMBA-UTIL LIBSAMBA-CONFIG dcerpc_samr RPC_NDR_LSA DYNCONFIG

swig_dcerpc_OBJ_FILES = librpc/rpc/dcerpc_wrap.o

[PYTHON::python_echo]
PRIVATE_DEPENDENCIES = RPC_NDR_ECHO

python_echo_OBJ_FILES = librpc/gen_ndr/py_echo.o

[PYTHON::python_winreg]
PRIVATE_DEPENDENCIES = RPC_NDR_WINREG python_misc

python_winreg_OBJ_FILES = librpc/gen_ndr/py_winreg.o

[PYTHON::python_dcerpc_misc]

python_dcerpc_misc_OBJ_FILES = librpc/gen_ndr/py_misc.o

[PYTHON::python_initshutdown]
PRIVATE_DEPENDENCIES = RPC_NDR_INITSHUTDOWN

python_initshutdown_OBJ_FILES = librpc/gen_ndr/py_initshutdown.o

[PYTHON::python_epmapper]

python_epmapper_OBJ_FILES = librpc/gen_ndr/py_epmapper.o

[PYTHON::python_mgmt]
PRIVATE_DEPENDENCIES = dcerpc_mgmt

python_mgmt_OBJ_FILES = librpc/gen_ndr/py_mgmt.o

[PYTHON::python_atsvc]
PRIVATE_DEPENDENCIES = dcerpc_atsvc

python_atsvc_OBJ_FILES = librpc/gen_ndr/py_atsvc.o

[PYTHON::python_samr]
PRIVATE_DEPENDENCIES = dcerpc_samr

python_samr_OBJ_FILES = librpc/gen_ndr/py_samr.o

[PYTHON::python_svcctl]
PRIVATE_DEPENDENCIES = RPC_NDR_SVCCTL

python_svcctl_OBJ_FILES = librpc/gen_ndr/py_svcctl.o

[PYTHON::python_lsa]
PRIVATE_DEPENDENCIES = RPC_NDR_LSA

python_lsa_OBJ_FILES = librpc/gen_ndr/py_lsa.o

[PYTHON::python_wkssvc]
PRIVATE_DEPENDENCIES = RPC_NDR_WKSSVC

python_wkssvc_OBJ_FILES = librpc/gen_ndr/py_wkssvc.o

[PYTHON::python_dcerpc_security]

python_dcerpc_security_OBJ_FILES = librpc/gen_ndr/py_security.o
