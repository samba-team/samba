ndrsrcdir = $(librpcsrcdir)/ndr
gen_ndrsrcdir = $(librpcsrcdir)/gen_ndr
dcerpcsrcdir = $(librpcsrcdir)/rpc

################################################
# Start SUBSYSTEM LIBNDR
[LIBRARY::LIBNDR]
PUBLIC_DEPENDENCIES = LIBSAMBA-ERRORS LIBTALLOC LIBSAMBA-UTIL CHARSET \
					  LIBSAMBA-HOSTCONFIG

LIBNDR_OBJ_FILES = $(addprefix $(ndrsrcdir)/, ndr_string.o) ../librpc/ndr/ndr_basic.o ../librpc/ndr/uuid.o ../librpc/ndr/ndr.o

$(eval $(call proto_header_template,$(ndrsrcdir)/libndr_proto.h,$(LIBNDR_OBJ_FILES:.o=.c)))

PC_FILES += ../librpc/ndr.pc
LIBNDR_VERSION = 0.0.1
LIBNDR_SOVERSION = 0

# End SUBSYSTEM LIBNDR
################################################

PUBLIC_HEADERS += $(ndrsrcdir)/libndr.h

#################################
# Start BINARY ndrdump
[BINARY::ndrdump]
INSTALLDIR = BINDIR
PRIVATE_DEPENDENCIES = \
		LIBSAMBA-HOSTCONFIG \
		LIBSAMBA-UTIL \
		LIBPOPT \
		POPT_SAMBA \
		NDR_TABLE \
		LIBSAMBA-ERRORS
# FIXME: ndrdump shouldn't have to depend on RPC...
# End BINARY ndrdump
#################################

ndrdump_OBJ_FILES = ../librpc/tools/ndrdump.o

MANPAGES += ../librpc/tools/ndrdump.1

################################################
# Start SUBSYSTEM NDR_COMPRESSION
[SUBSYSTEM::NDR_COMPRESSION]
PRIVATE_DEPENDENCIES = ZLIB LZXPRESS
PUBLIC_DEPENDENCIES = LIBSAMBA-ERRORS LIBNDR
# End SUBSYSTEM NDR_COMPRESSION
################################################

NDR_COMPRESSION_OBJ_FILES = ../librpc/ndr/ndr_compression.o

[SUBSYSTEM::NDR_SECURITY]
PUBLIC_DEPENDENCIES = NDR_MISC LIBSECURITY

NDR_SECURITY_OBJ_FILES = $(gen_ndrsrcdir)/ndr_security.o $(ndrsrcdir)/ndr_sec_helper.o 

PUBLIC_HEADERS += $(gen_ndrsrcdir)/security.h

[SUBSYSTEM::NDR_AUDIOSRV]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_AUDIOSRV_OBJ_FILES = $(gen_ndrsrcdir)/ndr_audiosrv.o

[SUBSYSTEM::NDR_DNSSERVER]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_DNSSERVER_OBJ_FILES = $(gen_ndrsrcdir)/ndr_dnsserver.o

[SUBSYSTEM::NDR_WINSTATION]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_WINSTATION_OBJ_FILES = $(gen_ndrsrcdir)/ndr_winstation.o

[SUBSYSTEM::NDR_ECHO]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_ECHO_OBJ_FILES = $(gen_ndrsrcdir)/ndr_echo.o

[SUBSYSTEM::NDR_IRPC]
PUBLIC_DEPENDENCIES = LIBNDR NDR_SECURITY NDR_NBT

NDR_IRPC_OBJ_FILES = $(gen_ndrsrcdir)/ndr_irpc.o

[SUBSYSTEM::NDR_DCOM]
PUBLIC_DEPENDENCIES = LIBNDR NDR_SECURITY NDR_ORPC

NDR_DCOM_OBJ_FILES = $(gen_ndrsrcdir)/ndr_dcom.o

[SUBSYSTEM::NDR_WMI]
PUBLIC_DEPENDENCIES = LIBNDR NDR_SECURITY NDR_DCOM

NDR_WMI_OBJ_FILES = $(gen_ndrsrcdir)/ndr_wmi.o $(ndrsrcdir)/ndr_wmi.o

[SUBSYSTEM::NDR_DSBACKUP]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_DSBACKUP_OBJ_FILES = $(gen_ndrsrcdir)/ndr_dsbackup.o

[SUBSYSTEM::NDR_EFS]
PUBLIC_DEPENDENCIES = LIBNDR NDR_SECURITY

NDR_EFS_OBJ_FILES = $(gen_ndrsrcdir)/ndr_efs.o

[SUBSYSTEM::NDR_MISC]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_MISC_OBJ_FILES = $(gen_ndrsrcdir)/ndr_misc.o ../librpc/ndr/ndr_misc.o

PUBLIC_HEADERS += $(gen_ndrsrcdir)/misc.h $(gen_ndrsrcdir)/ndr_misc.h

[SUBSYSTEM::NDR_ROT]
PUBLIC_DEPENDENCIES = LIBNDR NDR_ORPC

NDR_ROT_OBJ_FILES = $(gen_ndrsrcdir)/ndr_rot.o

[SUBSYSTEM::NDR_LSA]
PUBLIC_DEPENDENCIES = LIBNDR NDR_SECURITY

NDR_LSA_OBJ_FILES = $(gen_ndrsrcdir)/ndr_lsa.o

PUBLIC_HEADERS += $(gen_ndrsrcdir)/lsa.h

[SUBSYSTEM::NDR_DFS]
PUBLIC_DEPENDENCIES = LIBNDR NDR_MISC

NDR_DFS_OBJ_FILES = $(gen_ndrsrcdir)/ndr_dfs.o

[SUBSYSTEM::NDR_FRSRPC]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_FRSRPC_OBJ_FILES = $(gen_ndrsrcdir)/ndr_frsrpc.o

[SUBSYSTEM::NDR_FRSAPI]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_FRSAPI_OBJ_FILES = $(gen_ndrsrcdir)/ndr_frsapi.o

[SUBSYSTEM::NDR_DRSUAPI]
PUBLIC_DEPENDENCIES = LIBNDR NDR_COMPRESSION NDR_SECURITY NDR_SAMR ASN1_UTIL

NDR_DRSUAPI_OBJ_FILES = $(gen_ndrsrcdir)/ndr_drsuapi.o $(ndrsrcdir)/ndr_drsuapi.o

[SUBSYSTEM::NDR_DRSBLOBS]
PUBLIC_DEPENDENCIES = LIBNDR NDR_MISC NDR_DRSUAPI

NDR_DRSBLOBS_OBJ_FILES = $(gen_ndrsrcdir)/ndr_drsblobs.o $(ndrsrcdir)/ndr_drsblobs.o

[SUBSYSTEM::NDR_SASL_HELPERS]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_SASL_HELPERS_OBJ_FILES = $(gen_ndrsrcdir)/ndr_sasl_helpers.o

[SUBSYSTEM::NDR_POLICYAGENT]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_POLICYAGENT_OBJ_FILES = $(gen_ndrsrcdir)/ndr_policyagent.o

[SUBSYSTEM::NDR_UNIXINFO]
PUBLIC_DEPENDENCIES = LIBNDR NDR_SECURITY

NDR_UNIXINFO_OBJ_FILES = $(gen_ndrsrcdir)/ndr_unixinfo.o

[SUBSYSTEM::NDR_SAMR]
PUBLIC_DEPENDENCIES = LIBNDR NDR_MISC NDR_LSA NDR_SECURITY

NDR_SAMR_OBJ_FILES = $(gen_ndrsrcdir)/ndr_samr.o

PUBLIC_HEADERS += $(addprefix $(librpcsrcdir)/, gen_ndr/samr.h gen_ndr/ndr_samr.h gen_ndr/ndr_samr_c.h)

[SUBSYSTEM::NDR_NFS4ACL]
PUBLIC_DEPENDENCIES = LIBNDR NDR_MISC NDR_SECURITY

NDR_NFS4ACL_OBJ_FILES = $(gen_ndrsrcdir)/ndr_nfs4acl.o

[SUBSYSTEM::NDR_SPOOLSS]
PUBLIC_DEPENDENCIES = LIBNDR NDR_SPOOLSS_BUF NDR_SECURITY

NDR_SPOOLSS_OBJ_FILES = $(gen_ndrsrcdir)/ndr_spoolss.o

[SUBSYSTEM::NDR_SPOOLSS_BUF]

NDR_SPOOLSS_BUF_OBJ_FILES = $(ndrsrcdir)/ndr_spoolss_buf.o

$(eval $(call proto_header_template,$(ndrsrcdir)/ndr_spoolss_buf.h,$(NDR_SPOOLSS_BUF_OBJ_FILES:.o=.c)))

[SUBSYSTEM::NDR_WKSSVC]
PUBLIC_DEPENDENCIES = LIBNDR NDR_SRVSVC NDR_MISC NDR_SECURITY

NDR_WKSSVC_OBJ_FILES = $(gen_ndrsrcdir)/ndr_wkssvc.o

[SUBSYSTEM::NDR_SRVSVC]
PUBLIC_DEPENDENCIES = LIBNDR NDR_SVCCTL NDR_SECURITY

NDR_SRVSVC_OBJ_FILES = $(gen_ndrsrcdir)/ndr_srvsvc.o

[SUBSYSTEM::NDR_SVCCTL]
PUBLIC_DEPENDENCIES = LIBNDR NDR_MISC

NDR_SVCCTL_OBJ_FILES = $(gen_ndrsrcdir)/ndr_svcctl.o

PUBLIC_HEADERS += $(addprefix $(librpcsrcdir)/, gen_ndr/ndr_svcctl.h gen_ndr/svcctl.h)

[SUBSYSTEM::NDR_ATSVC]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_ATSVC_OBJ_FILES = $(gen_ndrsrcdir)/ndr_atsvc.o

PUBLIC_HEADERS += $(addprefix $(librpcsrcdir)/, gen_ndr/atsvc.h gen_ndr/ndr_atsvc.h)

[SUBSYSTEM::NDR_EVENTLOG]
PUBLIC_DEPENDENCIES = LIBNDR NDR_LSA

NDR_EVENTLOG_OBJ_FILES = $(gen_ndrsrcdir)/ndr_eventlog.o

[SUBSYSTEM::NDR_EPMAPPER]
PUBLIC_DEPENDENCIES = LIBNDR NDR_MISC

NDR_EPMAPPER_OBJ_FILES = $(gen_ndrsrcdir)/ndr_epmapper.o

[SUBSYSTEM::NDR_DBGIDL]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_DBGIDL_OBJ_FILES = $(gen_ndrsrcdir)/ndr_dbgidl.o

[SUBSYSTEM::NDR_DSSETUP]
PUBLIC_DEPENDENCIES = LIBNDR NDR_MISC

NDR_DSSETUP_OBJ_FILES = $(gen_ndrsrcdir)/ndr_dssetup.o

[SUBSYSTEM::NDR_MSGSVC]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_MSGSVC_OBJ_FILES = $(gen_ndrsrcdir)/ndr_msgsvc.o

[SUBSYSTEM::NDR_WINS]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_WINS_OBJ_FILES = $(gen_ndrsrcdir)/ndr_wins.o

[SUBSYSTEM::NDR_WINREG]
PUBLIC_DEPENDENCIES = LIBNDR NDR_INITSHUTDOWN NDR_SECURITY NDR_MISC

NDR_WINREG_OBJ_FILES = $(gen_ndrsrcdir)/ndr_winreg.o

[SUBSYSTEM::NDR_INITSHUTDOWN]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_INITSHUTDOWN_OBJ_FILES = $(gen_ndrsrcdir)/ndr_initshutdown.o

[SUBSYSTEM::NDR_MGMT]
PUBLIC_DEPENDENCIES = LIBNDR 

NDR_MGMT_OBJ_FILES = $(gen_ndrsrcdir)/ndr_mgmt.o

[SUBSYSTEM::NDR_PROTECTED_STORAGE]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_PROTECTED_STORAGE_OBJ_FILES = $(gen_ndrsrcdir)/ndr_protected_storage.o

[SUBSYSTEM::NDR_ORPC]
PUBLIC_DEPENDENCIES = LIBNDR 

NDR_ORPC_OBJ_FILES = $(gen_ndrsrcdir)/ndr_orpc.o $(ndrsrcdir)/ndr_orpc.o 

[SUBSYSTEM::NDR_OXIDRESOLVER]
PUBLIC_DEPENDENCIES = LIBNDR NDR_ORPC NDR_MISC

NDR_OXIDRESOLVER_OBJ_FILES = $(gen_ndrsrcdir)/ndr_oxidresolver.o

[SUBSYSTEM::NDR_REMACT]
PUBLIC_DEPENDENCIES = LIBNDR NDR_ORPC NDR_MISC

NDR_REMACT_OBJ_FILES = $(gen_ndrsrcdir)/ndr_remact.o

[SUBSYSTEM::NDR_WZCSVC]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_WZCSVC_OBJ_FILES = $(gen_ndrsrcdir)/ndr_wzcsvc.o

[SUBSYSTEM::NDR_BROWSER]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_BROWSER_OBJ_FILES = $(gen_ndrsrcdir)/ndr_browser.o

[SUBSYSTEM::NDR_W32TIME]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_W32TIME_OBJ_FILES = $(gen_ndrsrcdir)/ndr_w32time.o

[SUBSYSTEM::NDR_SCERPC]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_SCERPC_OBJ_FILES = $(gen_ndrsrcdir)/ndr_scerpc.o

[SUBSYSTEM::NDR_NTSVCS]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_NTSVCS_OBJ_FILES = $(gen_ndrsrcdir)/ndr_ntsvcs.o

[SUBSYSTEM::NDR_NETLOGON]
PUBLIC_DEPENDENCIES = LIBNDR NDR_SAMR NDR_LSA NDR_SECURITY

NDR_NETLOGON_OBJ_FILES = $(gen_ndrsrcdir)/ndr_netlogon.o

PUBLIC_HEADERS += $(addprefix $(librpcsrcdir)/, gen_ndr/netlogon.h)

[SUBSYSTEM::NDR_TRKWKS]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_TRKWKS_OBJ_FILES = $(gen_ndrsrcdir)/ndr_trkwks.o

[SUBSYSTEM::NDR_KEYSVC]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_KEYSVC_OBJ_FILES = $(gen_ndrsrcdir)/ndr_keysvc.o

[SUBSYSTEM::NDR_KRB5PAC]
PUBLIC_DEPENDENCIES = LIBNDR NDR_NETLOGON NDR_SECURITY

NDR_KRB5PAC_OBJ_FILES = $(gen_ndrsrcdir)/ndr_krb5pac.o ../librpc/ndr/ndr_krb5pac.o

[SUBSYSTEM::NDR_XATTR]
PUBLIC_DEPENDENCIES = LIBNDR NDR_SECURITY

NDR_XATTR_OBJ_FILES = $(gen_ndrsrcdir)/ndr_xattr.o

[SUBSYSTEM::NDR_OPENDB]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_OPENDB_OBJ_FILES = $(gen_ndrsrcdir)/ndr_opendb.o

[SUBSYSTEM::NDR_NOTIFY]
PUBLIC_DEPENDENCIES = LIBNDR

NDR_NOTIFY_OBJ_FILES = $(gen_ndrsrcdir)/ndr_notify.o

[SUBSYSTEM::NDR_SCHANNEL]
PUBLIC_DEPENDENCIES = LIBNDR NDR_NBT

NDR_SCHANNEL_OBJ_FILES = $(gen_ndrsrcdir)/ndr_schannel.o

[SUBSYSTEM::NDR_NBT]
PUBLIC_DEPENDENCIES = LIBNDR NDR_MISC NDR_NBT_BUF NDR_SVCCTL NDR_SECURITY NDR_SAMR LIBCLI_NDR_NETLOGON

NDR_NBT_OBJ_FILES = $(gen_ndrsrcdir)/ndr_nbt.o

PUBLIC_HEADERS += $(gen_ndrsrcdir)/nbt.h

[SUBSYSTEM::NDR_NTP_SIGND]
PUBLIC_DEPENDENCIES = LIBNDR 

NDR_NTP_SIGND_OBJ_FILES = $(gen_ndrsrcdir)/ndr_ntp_signd.o

[SUBSYSTEM::NDR_WINSREPL]
PUBLIC_DEPENDENCIES = LIBNDR NDR_NBT

NDR_WINSREPL_OBJ_FILES = $(gen_ndrsrcdir)/ndr_winsrepl.o

[SUBSYSTEM::NDR_WINBIND]
PUBLIC_DEPENDENCIES = LIBNDR NDR_NETLOGON

NDR_WINBIND_OBJ_FILES = $(gen_ndrsrcdir)/ndr_winbind.o
#PUBLIC_HEADERS += $(gen_ndrsrcdir)/winbind.h

$(librpcsrcdir)/idl-deps:
	$(PERL) $(librpcsrcdir)/idl-deps.pl $(librpcsrcdir)/idl/*.idl >$@

clean:: 
	rm -f $(librpcsrcdir)/idl-deps

-include $(librpcsrcdir)/idl-deps

$(gen_ndrsrcdir)/tables.c: $(IDL_NDR_PARSE_H_FILES)
	@echo Generating $@
	@$(PERL) $(librpcsrcdir)/tables.pl --output=$@ $^ > $(gen_ndrsrcdir)/tables.x
	@mv $(gen_ndrsrcdir)/tables.x $@

[SUBSYSTEM::NDR_TABLE]
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
	NDR_SASL_HELPERS NDR_NOTIFY NDR_WINBIND NDR_FRSRPC NDR_FRSAPI NDR_NFS4ACL NDR_NTP_SIGND \
	NDR_DCOM NDR_WMI

NDR_TABLE_OBJ_FILES = $(ndrsrcdir)/ndr_table.o $(gen_ndrsrcdir)/tables.o

$(eval $(call proto_header_template,$(ndrsrcdir)/ndr_table.h,$(NDR_TABLE_OBJ_FILES:.o=.c)))

[SUBSYSTEM::RPC_NDR_ROT]
PUBLIC_DEPENDENCIES = NDR_ROT dcerpc

RPC_NDR_ROT_OBJ_FILES = $(gen_ndrsrcdir)/ndr_rot_c.o

[SUBSYSTEM::RPC_NDR_AUDIOSRV]
PUBLIC_DEPENDENCIES = NDR_AUDIOSRV dcerpc

RPC_NDR_AUDIOSRV_OBJ_FILES = $(gen_ndrsrcdir)/ndr_audiosrv_c.o

[SUBSYSTEM::RPC_NDR_ECHO]
PUBLIC_DEPENDENCIES = dcerpc NDR_ECHO

RPC_NDR_ECHO_OBJ_FILES = $(gen_ndrsrcdir)/ndr_echo_c.o

[SUBSYSTEM::RPC_NDR_DSBACKUP]
PUBLIC_DEPENDENCIES = dcerpc NDR_DSBACKUP

RPC_NDR_DSBACKUP_OBJ_FILES = $(gen_ndrsrcdir)/ndr_dsbackup_c.o

[SUBSYSTEM::RPC_NDR_EFS]
PUBLIC_DEPENDENCIES = dcerpc NDR_EFS

RPC_NDR_EFS_OBJ_FILES = $(gen_ndrsrcdir)/ndr_efs_c.o

[SUBSYSTEM::RPC_NDR_LSA]
PUBLIC_DEPENDENCIES = dcerpc NDR_LSA

RPC_NDR_LSA_OBJ_FILES = $(gen_ndrsrcdir)/ndr_lsa_c.o

[SUBSYSTEM::RPC_NDR_DFS]
PUBLIC_DEPENDENCIES = dcerpc NDR_DFS

RPC_NDR_DFS_OBJ_FILES = $(gen_ndrsrcdir)/ndr_dfs_c.o

[SUBSYSTEM::RPC_NDR_FRSAPI]
PUBLIC_DEPENDENCIES = dcerpc NDR_FRSAPI

RPC_NDR_FRSAPI_OBJ_FILES = $(gen_ndrsrcdir)/ndr_frsapi_c.o

[SUBSYSTEM::RPC_NDR_DRSUAPI]
PUBLIC_DEPENDENCIES = dcerpc NDR_DRSUAPI

RPC_NDR_DRSUAPI_OBJ_FILES = $(gen_ndrsrcdir)/ndr_drsuapi_c.o

[SUBSYSTEM::RPC_NDR_POLICYAGENT]
PUBLIC_DEPENDENCIES = dcerpc NDR_POLICYAGENT

RPC_NDR_POLICYAGENT_OBJ_FILES = $(gen_ndrsrcdir)/ndr_policyagent_c.o

[SUBSYSTEM::RPC_NDR_UNIXINFO]
PUBLIC_DEPENDENCIES = dcerpc NDR_UNIXINFO

RPC_NDR_UNIXINFO_OBJ_FILES = $(gen_ndrsrcdir)/ndr_unixinfo_c.o

[SUBSYSTEM::RPC_NDR_IRPC]
PUBLIC_DEPENDENCIES = dcerpc NDR_IRPC

RPC_NDR_IRPC_OBJ_FILES = $(gen_ndrsrcdir)/ndr_irpc_c.o

[LIBRARY::dcerpc_samr]
PUBLIC_DEPENDENCIES = dcerpc NDR_SAMR 

PC_FILES += $(librpcsrcdir)/dcerpc_samr.pc

dcerpc_samr_VERSION = 0.0.1
dcerpc_samr_SOVERSION = 0
dcerpc_samr_OBJ_FILES = $(gen_ndrsrcdir)/ndr_samr_c.o

[SUBSYSTEM::RPC_NDR_SPOOLSS]
PUBLIC_DEPENDENCIES = dcerpc NDR_SPOOLSS

RPC_NDR_SPOOLSS_OBJ_FILES = $(gen_ndrsrcdir)/ndr_spoolss_c.o

[SUBSYSTEM::RPC_NDR_WKSSVC]
PUBLIC_DEPENDENCIES = dcerpc NDR_WKSSVC

RPC_NDR_WKSSVC_OBJ_FILES = $(gen_ndrsrcdir)/ndr_wkssvc_c.o

[SUBSYSTEM::RPC_NDR_SRVSVC]
PUBLIC_DEPENDENCIES = dcerpc NDR_SRVSVC

RPC_NDR_SRVSVC_OBJ_FILES = $(gen_ndrsrcdir)/ndr_srvsvc_c.o

[SUBSYSTEM::RPC_NDR_SVCCTL]
PUBLIC_DEPENDENCIES = dcerpc NDR_SVCCTL

RPC_NDR_SVCCTL_OBJ_FILES = $(gen_ndrsrcdir)/ndr_svcctl_c.o

PUBLIC_HEADERS += $(gen_ndrsrcdir)/ndr_svcctl_c.h

[LIBRARY::dcerpc_atsvc]
PUBLIC_DEPENDENCIES = dcerpc NDR_ATSVC

dcerpc_atsvc_VERSION = 0.0.1
dcerpc_atsvc_SOVERSION = 0

dcerpc_atsvc_OBJ_FILES = $(gen_ndrsrcdir)/ndr_atsvc_c.o
PC_FILES += $(librpcsrcdir)/dcerpc_atsvc.pc

PUBLIC_HEADERS += $(gen_ndrsrcdir)/ndr_atsvc_c.h

[SUBSYSTEM::RPC_NDR_EVENTLOG]
PUBLIC_DEPENDENCIES = dcerpc NDR_EVENTLOG

RPC_NDR_EVENTLOG_OBJ_FILES = $(gen_ndrsrcdir)/ndr_eventlog_c.o

[SUBSYSTEM::RPC_NDR_EPMAPPER]
PUBLIC_DEPENDENCIES = NDR_EPMAPPER 

RPC_NDR_EPMAPPER_OBJ_FILES = $(gen_ndrsrcdir)/ndr_epmapper_c.o

[SUBSYSTEM::RPC_NDR_DBGIDL]
PUBLIC_DEPENDENCIES = dcerpc NDR_DBGIDL

RPC_NDR_DBGIDL_OBJ_FILES = $(gen_ndrsrcdir)/ndr_dbgidl_c.o

[SUBSYSTEM::RPC_NDR_DSSETUP]
PUBLIC_DEPENDENCIES = dcerpc NDR_DSSETUP

RPC_NDR_DSSETUP_OBJ_FILES = $(gen_ndrsrcdir)/ndr_dssetup_c.o

[SUBSYSTEM::RPC_NDR_MSGSVC]
PUBLIC_DEPENDENCIES = dcerpc NDR_MSGSVC

RPC_NDR_MSGSVC_OBJ_FILES = $(gen_ndrsrcdir)/ndr_msgsvc_c.o

[SUBSYSTEM::RPC_NDR_WINS]
PUBLIC_DEPENDENCIES = dcerpc NDR_WINS

RPC_NDR_WINS_OBJ_FILES = $(gen_ndrsrcdir)/ndr_wins_c.o

[SUBSYSTEM::RPC_NDR_WINREG]
PUBLIC_DEPENDENCIES = dcerpc NDR_WINREG

RPC_NDR_WINREG_OBJ_FILES = $(gen_ndrsrcdir)/ndr_winreg_c.o

[SUBSYSTEM::RPC_NDR_INITSHUTDOWN]
PUBLIC_DEPENDENCIES = dcerpc NDR_INITSHUTDOWN

RPC_NDR_INITSHUTDOWN_OBJ_FILES = $(gen_ndrsrcdir)/ndr_initshutdown_c.o

[SUBSYSTEM::RPC_NDR_MGMT]
PRIVATE_DEPENDENCIES = NDR_MGMT

RPC_NDR_MGMT_OBJ_FILES = $(gen_ndrsrcdir)/ndr_mgmt_c.o

[SUBSYSTEM::RPC_NDR_PROTECTED_STORAGE]
PUBLIC_DEPENDENCIES = dcerpc NDR_PROTECTED_STORAGE

RPC_NDR_PROTECTED_STORAGE_OBJ_FILES = $(gen_ndrsrcdir)/ndr_protected_storage_c.o

[SUBSYSTEM::RPC_NDR_OXIDRESOLVER]
PUBLIC_DEPENDENCIES = dcerpc NDR_OXIDRESOLVER

RPC_NDR_OXIDRESOLVER_OBJ_FILES = $(gen_ndrsrcdir)/ndr_oxidresolver_c.o

[SUBSYSTEM::RPC_NDR_REMACT]
PUBLIC_DEPENDENCIES = dcerpc NDR_REMACT

RPC_NDR_REMACT_OBJ_FILES = $(gen_ndrsrcdir)/ndr_remact_c.o

[SUBSYSTEM::RPC_NDR_WZCSVC]
PUBLIC_DEPENDENCIES = dcerpc NDR_WZCSVC

RPC_NDR_WZCSVC_OBJ_FILES = $(gen_ndrsrcdir)/ndr_wzcsvc_c.o

[SUBSYSTEM::RPC_NDR_W32TIME]
PUBLIC_DEPENDENCIES = dcerpc NDR_W32TIME

RPC_NDR_W32TIME_OBJ_FILES = $(gen_ndrsrcdir)/ndr_w32time_c.o

[SUBSYSTEM::RPC_NDR_SCERPC]
PUBLIC_DEPENDENCIES = dcerpc NDR_SCERPC

RPC_NDR_SCERPC_OBJ_FILES = $(gen_ndrsrcdir)/ndr_scerpc_c.o

[SUBSYSTEM::RPC_NDR_NTSVCS]
PUBLIC_DEPENDENCIES = dcerpc NDR_NTSVCS

RPC_NDR_NTSVCS_OBJ_FILES = $(gen_ndrsrcdir)/ndr_ntsvcs_c.o

[SUBSYSTEM::RPC_NDR_NETLOGON]
PUBLIC_DEPENDENCIES = NDR_NETLOGON

RPC_NDR_NETLOGON_OBJ_FILES = $(gen_ndrsrcdir)/ndr_netlogon_c.o

[SUBSYSTEM::RPC_NDR_TRKWKS]
PUBLIC_DEPENDENCIES = dcerpc NDR_TRKWKS

RPC_NDR_TRKWKS_OBJ_FILES = $(gen_ndrsrcdir)/ndr_trkwks_c.o

[SUBSYSTEM::RPC_NDR_KEYSVC]
PUBLIC_DEPENDENCIES = dcerpc NDR_KEYSVC

RPC_NDR_KEYSVC_OBJ_FILES = $(gen_ndrsrcdir)/ndr_keysvc_c.o

[SUBSYSTEM::NDR_DCERPC]
PUBLIC_DEPENDENCIES = LIBNDR NDR_MISC

NDR_DCERPC_OBJ_FILES = $(gen_ndrsrcdir)/ndr_dcerpc.o

PUBLIC_HEADERS += $(addprefix $(librpcsrcdir)/, gen_ndr/dcerpc.h gen_ndr/ndr_dcerpc.h)

################################################
# Start SUBSYSTEM dcerpc
[LIBRARY::dcerpc]
PRIVATE_DEPENDENCIES = \
		samba-socket LIBCLI_RESOLVE LIBCLI_SMB LIBCLI_SMB2 \
		LIBNDR NDR_DCERPC RPC_NDR_EPMAPPER \
		NDR_SCHANNEL RPC_NDR_NETLOGON \
		RPC_NDR_MGMT \
		gensec LIBCLI_AUTH LIBCLI_RAW \
		LP_RESOLVE
PUBLIC_DEPENDENCIES = CREDENTIALS 
# End SUBSYSTEM dcerpc
################################################

PC_FILES += $(librpcsrcdir)/dcerpc.pc
dcerpc_VERSION = 0.0.1
dcerpc_SOVERSION = 0

dcerpc_OBJ_FILES = $(addprefix $(dcerpcsrcdir)/, dcerpc.o dcerpc_auth.o dcerpc_schannel.o dcerpc_util.o \
				  dcerpc_error.o dcerpc_smb.o dcerpc_smb2.o dcerpc_sock.o dcerpc_connect.o dcerpc_secondary.o) \
					../librpc/rpc/binding.o

$(eval $(call proto_header_template,$(dcerpcsrcdir)/dcerpc_proto.h,$(dcerpc_OBJ_FILES:.o=.c)))


PUBLIC_HEADERS += $(addprefix $(librpcsrcdir)/, rpc/dcerpc.h \
			gen_ndr/mgmt.h gen_ndr/ndr_mgmt.h gen_ndr/ndr_mgmt_c.h \
			gen_ndr/epmapper.h gen_ndr/ndr_epmapper.h gen_ndr/ndr_epmapper_c.h)


[PYTHON::python_dcerpc]
LIBRARY_REALNAME = samba/dcerpc/base.$(SHLIBEXT)
PUBLIC_DEPENDENCIES = LIBCLI_SMB NDR_MISC LIBSAMBA-UTIL LIBSAMBA-HOSTCONFIG dcerpc_samr RPC_NDR_LSA DYNCONFIG swig_credentials param

python_dcerpc_OBJ_FILES = $(dcerpcsrcdir)/pyrpc.o

$(eval $(call python_py_module_template,samba/dcerpc/__init__.py,$(dcerpcsrcdir)/dcerpc.py))


[PYTHON::python_echo]
LIBRARY_REALNAME = samba/dcerpc/echo.$(SHLIBEXT)
PRIVATE_DEPENDENCIES = RPC_NDR_ECHO PYTALLOC param swig_credentials python_dcerpc

python_echo_OBJ_FILES = $(gen_ndrsrcdir)/py_echo.o

[PYTHON::python_winreg]
LIBRARY_REALNAME = samba/dcerpc/winreg.$(SHLIBEXT)
PRIVATE_DEPENDENCIES = RPC_NDR_WINREG python_misc PYTALLOC param swig_credentials python_dcerpc_misc python_lsa python_dcerpc

python_winreg_OBJ_FILES = $(gen_ndrsrcdir)/py_winreg.o

[PYTHON::python_dcerpc_misc]
LIBRARY_REALNAME = samba/dcerpc/misc.$(SHLIBEXT)
PRIVATE_DEPENDENCIES = PYTALLOC python_dcerpc

python_dcerpc_misc_OBJ_FILES = $(gen_ndrsrcdir)/py_misc.o

[PYTHON::python_initshutdown]
LIBRARY_REALNAME = samba/dcerpc/initshutdown.$(SHLIBEXT)
PRIVATE_DEPENDENCIES = RPC_NDR_INITSHUTDOWN PYTALLOC param swig_credentials python_lsa python_dcerpc_security python_dcerpc

python_initshutdown_OBJ_FILES = $(gen_ndrsrcdir)/py_initshutdown.o

[PYTHON::python_epmapper]
LIBRARY_REALNAME = samba/dcerpc/epmapper.$(SHLIBEXT)
PRIVATE_DEPENDENCIES =  dcerpc PYTALLOC param swig_credentials python_dcerpc_misc python_dcerpc

python_epmapper_OBJ_FILES = $(gen_ndrsrcdir)/py_epmapper.o

[PYTHON::python_mgmt]
LIBRARY_REALNAME = samba/dcerpc/mgmt.$(SHLIBEXT)
PRIVATE_DEPENDENCIES = PYTALLOC param swig_credentials dcerpc python_dcerpc_misc python_dcerpc

python_mgmt_OBJ_FILES = $(gen_ndrsrcdir)/py_mgmt.o

[PYTHON::python_atsvc]
LIBRARY_REALNAME = samba/dcerpc/atsvc.$(SHLIBEXT)
PRIVATE_DEPENDENCIES = dcerpc_atsvc PYTALLOC param swig_credentials  python_dcerpc

python_atsvc_OBJ_FILES = $(gen_ndrsrcdir)/py_atsvc.o

[PYTHON::python_dcerpc_nbt]
LIBRARY_REALNAME = samba/nbt.$(SHLIBEXT)
PRIVATE_DEPENDENCIES = NDR_NBT PYTALLOC param swig_credentials python_dcerpc python_dcerpc_misc python_dcerpc_security

python_dcerpc_nbt_OBJ_FILES = $(gen_ndrsrcdir)/py_nbt.o

[PYTHON::python_samr]
LIBRARY_REALNAME = samba/dcerpc/samr.$(SHLIBEXT)
PRIVATE_DEPENDENCIES = dcerpc_samr PYTALLOC python_dcerpc_security python_lsa python_dcerpc_misc swig_credentials param python_dcerpc

python_samr_OBJ_FILES = $(gen_ndrsrcdir)/py_samr.o

[PYTHON::python_svcctl]
LIBRARY_REALNAME = samba/dcerpc/svcctl.$(SHLIBEXT)
PRIVATE_DEPENDENCIES = RPC_NDR_SVCCTL PYTALLOC param swig_credentials python_dcerpc_misc python_dcerpc

python_svcctl_OBJ_FILES = $(gen_ndrsrcdir)/py_svcctl.o

[PYTHON::python_lsa]
LIBRARY_REALNAME = samba/dcerpc/lsa.$(SHLIBEXT)
PRIVATE_DEPENDENCIES = RPC_NDR_LSA PYTALLOC param swig_credentials python_dcerpc_security python_dcerpc

python_lsa_OBJ_FILES = $(gen_ndrsrcdir)/py_lsa.o

[PYTHON::python_wkssvc]
LIBRARY_REALNAME = samba/dcerpc/wkssvc.$(SHLIBEXT)
PRIVATE_DEPENDENCIES = RPC_NDR_WKSSVC PYTALLOC param swig_credentials python_lsa python_dcerpc_security python_dcerpc

python_wkssvc_OBJ_FILES = $(gen_ndrsrcdir)/py_wkssvc.o

[PYTHON::python_dfs]
LIBRARY_REALNAME = samba/dcerpc/dfs.$(SHLIBEXT)
PRIVATE_DEPENDENCIES = RPC_NDR_DFS PYTALLOC param swig_credentials python_dcerpc_misc python_dcerpc

python_dfs_OBJ_FILES = $(gen_ndrsrcdir)/py_dfs.o

[PYTHON::python_unixinfo]
LIBRARY_REALNAME = samba/dcerpc/unixinfo.$(SHLIBEXT)
PRIVATE_DEPENDENCIES = RPC_NDR_UNIXINFO PYTALLOC param swig_credentials python_dcerpc_security python_dcerpc_misc python_dcerpc

python_unixinfo_OBJ_FILES = $(gen_ndrsrcdir)/py_unixinfo.o

[PYTHON::python_irpc]
LIBRARY_REALNAME = samba/irpc.$(SHLIBEXT)
PRIVATE_DEPENDENCIES = RPC_NDR_IRPC PYTALLOC param swig_credentials python_dcerpc_security python_dcerpc_misc python_dcerpc python_dcerpc_nbt

python_irpc_OBJ_FILES = $(gen_ndrsrcdir)/py_irpc.o

[PYTHON::python_drsuapi]
LIBRARY_REALNAME = samba/dcerpc/drsuapi.$(SHLIBEXT)
PRIVATE_DEPENDENCIES = RPC_NDR_DRSUAPI PYTALLOC param swig_credentials python_dcerpc_misc python_dcerpc_security python_dcerpc

python_drsuapi_OBJ_FILES = $(gen_ndrsrcdir)/py_drsuapi.o

[PYTHON::python_dcerpc_security]
LIBRARY_REALNAME = samba/dcerpc/security.$(SHLIBEXT)
PRIVATE_DEPENDENCIES = PYTALLOC python_dcerpc_misc python_dcerpc

python_dcerpc_security_OBJ_FILES = $(gen_ndrsrcdir)/py_security.o

$(IDL_HEADER_FILES) $(IDL_NDR_PARSE_H_FILES) $(IDL_NDR_PARSE_C_FILES) \
	$(IDL_NDR_CLIENT_C_FILES) $(IDL_NDR_CLIENT_H_FILES) \
	$(IDL_NDR_SERVER_C_FILES) $(IDL_SWIG_FILES) \
	$(IDL_NDR_PY_C_FILES) $(IDL_NDR_PY_H_FILES): idl

idl_full:: $(pidldir)/lib/Parse/Pidl/IDL.pm $(pidldir)/lib/Parse/Pidl/Expr.pm 
	@CPP="$(CPP)" PIDL="$(PIDL)" $(librpcsrcdir)/scripts/build_idl.sh FULL $(librpcsrcdir)/idl $(librpcsrcdir)/gen_ndr

idl:: $(pidldir)/lib/Parse/Pidl/IDL.pm $(pidldir)/lib/Parse/Pidl/Expr.pm 
	@CPP="$(CPP)" PIDL="$(PIDL)" $(librpcsrcdir)/scripts/build_idl.sh PARTIAL $(librpcsrcdir)/idl $(librpcsrcdir)/gen_ndr


