# DCERPC Server subsystem

################################################
# Start SUBSYSTEM DCERPC_COMMON
[SUBSYSTEM::DCERPC_COMMON]
ADD_OBJ_FILES = \
		rpc_server/common/server_info.o \
		rpc_server/common/share_info.o \
		rpc_server/common/gendb.o
#
# End SUBSYSTEM DCERPC_COMMON
################################################

################################################
# Start SUBSYSTEM SAMDB
[SUBSYSTEM::SAMDB]
INIT_OBJ_FILES = \
		rpc_server/samr/samdb.o
ADD_OBJ_FILES = \
		rpc_server/samr/samr_utils.o
REQUIRED_SUBSYSTEMS = \
		LIBLDB
#
# End SUBSYSTEM SAMDB
################################################

################################################
# Start MODULE dcerpc_rpcecho
[MODULE::dcerpc_rpcecho]
INIT_OBJ_FILES = \
		rpc_server/echo/rpc_echo.o
# End MODULE dcerpc_rpcecho
################################################

################################################
# Start MODULE dcerpc_epmapper
[MODULE::dcerpc_epmapper]
INIT_OBJ_FILES = \
		rpc_server/epmapper/rpc_epmapper.o
# End MODULE dcerpc_epmapper
################################################

################################################
# Start MODULE dcerpc_remote
[MODULE::dcerpc_remote]
INIT_OBJ_FILES = \
		rpc_server/remote/dcesrv_remote.o
REQUIRED_SUBSYSTEMS = \
		LIBSMB
# End MODULE dcerpc_remote
################################################

################################################
# Start MODULE dcerpc_srvsvc
[MODULE::dcerpc_srvsvc]
INIT_OBJ_FILES = \
		rpc_server/srvsvc/dcesrv_srvsvc.o
REQUIRED_SUBSYSTEMS = \
		DCERPC_COMMON
# End MODULE dcerpc_srvsvc
################################################

################################################
# Start MODULE dcerpc_wkssvc
[MODULE::dcerpc_wkssvc]
INIT_OBJ_FILES = \
		rpc_server/wkssvc/dcesrv_wkssvc.o
REQUIRED_SUBSYSTEMS = \
		DCERPC_COMMON
# End MODULE dcerpc_wkssvc
################################################

################################################
# Start MODULE dcerpc_samr
[MODULE::dcerpc_samr]
INIT_OBJ_FILES = \
		rpc_server/samr/dcesrv_samr.o
ADD_OBJ_FILES = \
		rpc_server/samr/samr_password.o
REQUIRED_SUBSYSTEMS = \
		SAMDB \
		DCERPC_COMMON
# End MODULE dcerpc_samr
################################################

################################################
# Start MODULE dcerpc_winreg
[MODULE::dcerpc_winreg]
INIT_OBJ_FILES = \
		rpc_server/winreg/rpc_winreg.o
REQUIRED_SUBSYSTEMS = \
		REGISTRY
# End MODULE dcerpc_winreg
################################################

################################################
# Start MODULE dcerpc_netlogon
[MODULE::dcerpc_netlogon]
INIT_OBJ_FILES = \
		rpc_server/netlogon/dcerpc_netlogon.o
ADD_OBJ_FILES = \
		rpc_server/netlogon/schannel_state.o
REQUIRED_SUBSYSTEMS = \
		DCERPC_COMMON
# End MODULE dcerpc_netlogon
################################################

################################################
# Start MODULE dcerpc_lsa
[MODULE::dcerpc_lsarpc]
INIT_OBJ_FILES = \
		rpc_server/lsa/dcesrv_lsa.o
REQUIRED_SUBSYSTEMS = \
		SAMDB \
		DCERPC_COMMON
# End MODULE dcerpc_lsa
################################################

################################################
# Start MODULE dcerpc_spoolss
[MODULE::dcerpc_spoolss]
INIT_OBJ_FILES = \
		rpc_server/spoolss/dcesrv_spoolss.o \
		rpc_server/spoolss/spoolssdb.o
REQUIRED_SUBSYSTEMS = \
		DCERPC_COMMON
# End MODULE dcerpc_lsa
################################################

################################################
# Start SUBSYSTEM DCERPC
[SUBSYSTEM::DCERPC]
INIT_OBJ_FILES = \
		rpc_server/dcerpc_server.o
ADD_OBJ_FILES = \
		rpc_server/dcerpc_tcp.o \
		rpc_server/dcesrv_auth.o \
		rpc_server/dcesrv_crypto.o \
		rpc_server/dcesrv_crypto_ntlmssp.o \
		rpc_server/dcesrv_crypto_schannel.o \
		rpc_server/handles.o
#
# End SUBSYSTEM DCERPC
################################################
