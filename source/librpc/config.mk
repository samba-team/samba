################################################
# Start SUBSYSTEM LIBNDR_RAW
[SUBSYSTEM::LIBNDR_RAW]
INIT_OBJ_FILES = \
		librpc/ndr/ndr.o
ADD_OBJ_FILES = \
		librpc/ndr/ndr_basic.o \
		librpc/ndr/ndr_sec.o \
		librpc/ndr/ndr_spoolss_buf.o \
		librpc/ndr/ndr_dcom.o 
# End SUBSYSTEM LIBNDR_RAW
################################################

################################################
# Start SUBSYSTEM LIBRPC_RAW
[SUBSYSTEM::LIBRPC_RAW]
INIT_OBJ_FILES = \
		librpc/rpc/dcerpc.o
ADD_OBJ_FILES = \
		librpc/rpc/dcerpc_auth.o \
		librpc/rpc/dcerpc_util.o \
		librpc/rpc/dcerpc_error.o \
		librpc/rpc/dcerpc_schannel.o \
		librpc/rpc/dcerpc_ntlm.o \
		librpc/rpc/dcerpc_spnego.o \
		librpc/rpc/dcerpc_smb.o \
		librpc/rpc/dcerpc_sock.o
REQUIRED_SUBSYSTEMS = SOCKET
# End SUBSYSTEM LIBRPC_RAW
################################################

################################################
# Start SUBSYSTEM LIBNDR_GEN
[SUBSYSTEM::LIBNDR_GEN]
INIT_FUNCTION = \
		dcerpc_audiosrv_init \
		dcerpc_dcerpc_init \
		dcerpc_echo_init \
		dcerpc_exchange_init \
		dcerpc_dsbackup_init \
		dcerpc_efs_init \
		dcerpc_misc_init \
		dcerpc_lsa_init \
		dcerpc_lsads_init \
		dcerpc_dfs_init \
		dcerpc_drsuapi_init \
		dcerpc_policyagent_init \
		dcerpc_samr_init \
		dcerpc_spoolss_init \
		dcerpc_wkssvc_init \
		dcerpc_srvsvc_init \
		dcerpc_svcctl_init \
		dcerpc_atsvc_init \
		dcerpc_eventlog_init \
		dcerpc_epmapper_init \
		dcerpc_dbgidl_init \
		dcerpc_dssetup_init \
		dcerpc_msgsvc_init \
		dcerpc_wins_init \
		dcerpc_winreg_init \
		dcerpc_mgmt_init \
		dcerpc_protected_storage_init \
		dcerpc_dcom_init \
		dcerpc_oxidresolver_init \
		dcerpc_remact_init \
		dcerpc_wzcsvc_init \
		dcerpc_browser_init \
		dcerpc_w32time_init \
		dcerpc_scerpc_init \
		dcerpc_ntsvcs_init \
		dcerpc_netlogon_init \
		dcerpc_trkwks_init \
		dcerpc_keysvc_init \
		dcerpc_krb5pac_init \
		dcerpc_xattr_init \
		dcerpc_schannel_init

NOPROTO = YES
ADD_OBJ_FILES = \
		librpc/gen_ndr/ndr_audiosrv.o \
		librpc/gen_ndr/ndr_dcerpc.o \
		librpc/gen_ndr/ndr_echo.o \
		librpc/gen_ndr/ndr_exchange.o \
		librpc/gen_ndr/ndr_dsbackup.o \
		librpc/gen_ndr/ndr_efs.o \
		librpc/gen_ndr/ndr_misc.o \
		librpc/gen_ndr/ndr_lsa.o \
		librpc/gen_ndr/ndr_lsads.o \
		librpc/gen_ndr/ndr_dfs.o \
		librpc/gen_ndr/ndr_drsuapi.o \
		librpc/gen_ndr/ndr_policyagent.o \
		librpc/gen_ndr/ndr_samr.o \
		librpc/gen_ndr/ndr_spoolss.o \
		librpc/gen_ndr/ndr_wkssvc.o \
		librpc/gen_ndr/ndr_srvsvc.o \
		librpc/gen_ndr/ndr_svcctl.o \
		librpc/gen_ndr/ndr_atsvc.o \
		librpc/gen_ndr/ndr_eventlog.o \
		librpc/gen_ndr/ndr_epmapper.o \
		librpc/gen_ndr/ndr_dbgidl.o \
		librpc/gen_ndr/ndr_dssetup.o \
		librpc/gen_ndr/ndr_msgsvc.o \
		librpc/gen_ndr/ndr_wins.o \
		librpc/gen_ndr/ndr_winreg.o \
		librpc/gen_ndr/ndr_mgmt.o \
		librpc/gen_ndr/ndr_protected_storage.o \
		librpc/gen_ndr/ndr_dcom.o \
		librpc/gen_ndr/ndr_oxidresolver.o \
		librpc/gen_ndr/ndr_remact.o \
		librpc/gen_ndr/ndr_wzcsvc.o \
		librpc/gen_ndr/ndr_browser.o \
		librpc/gen_ndr/ndr_w32time.o \
		librpc/gen_ndr/ndr_scerpc.o \
		librpc/gen_ndr/ndr_ntsvcs.o \
		librpc/gen_ndr/ndr_netlogon.o \
		librpc/gen_ndr/ndr_trkwks.o \
		librpc/gen_ndr/ndr_keysvc.o \
		librpc/gen_ndr/ndr_krb5pac.o \
		librpc/gen_ndr/ndr_xattr.o \
		librpc/gen_ndr/ndr_schannel.o
# End SUBSYSTEM LIBNDR_GEN
################################################

################################################
# Start SUBSYSTEM LIBRPC
[SUBSYSTEM::LIBRPC]
REQUIRED_SUBSYSTEMS = LIBNDR_RAW LIBNDR_GEN LIBRPC_RAW LIBSMB LIBDCOM
# End SUBSYSTEM LIBRPC
################################################
