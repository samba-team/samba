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
REQUIRED_SUBSYSTEMS = LIBSMB SOCKET
# End SUBSYSTEM LIBRPC_RAW
################################################

################################################
# Start SUBSYSTEM LIBNDR_GEN
[SUBSYSTEM::LIBNDR_GEN]
NOPROTO = YES
INIT_FUNCTION = librpc_init
INIT_OBJ_FILES = \
		librpc/gen_ndr/tables.o
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
REQUIRED_SUBSYSTEMS = LIBNDR_RAW LIBNDR_GEN LIBRPC_RAW LIBDCOM
# End SUBSYSTEM LIBRPC
################################################
