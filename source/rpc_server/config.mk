# DCERPC Server subsystem

################################################
# Start SUBSYSTEM DCERPC_COMMON
[SUBSYSTEM::DCERPC_COMMON]
PUBLIC_PROTO_HEADER = common/proto.h
PUBLIC_HEADERS = common/common.h
OBJ_FILES = \
		common/server_info.o \
		common/share_info.o
#
# End SUBSYSTEM DCERPC_COMMON
################################################

################################################
# Start MODULE dcerpc_rpcecho
[MODULE::dcerpc_rpcecho]
INIT_FUNCTION = dcerpc_server_rpcecho_init
SUBSYSTEM = dcerpc_server
OBJ_FILES = \
		echo/rpc_echo.o
PUBLIC_DEPENDENCIES = NDR_ECHO 
# End MODULE dcerpc_rpcecho
################################################

################################################
# Start MODULE dcerpc_epmapper
[MODULE::dcerpc_epmapper]
INIT_FUNCTION = dcerpc_server_epmapper_init
SUBSYSTEM = dcerpc_server
OBJ_FILES = \
		epmapper/rpc_epmapper.o
PUBLIC_DEPENDENCIES = NDR_EPMAPPER
# End MODULE dcerpc_epmapper
################################################

################################################
# Start MODULE dcerpc_remote
[MODULE::dcerpc_remote]
INIT_FUNCTION = dcerpc_server_remote_init
SUBSYSTEM = dcerpc_server
OBJ_FILES = \
		remote/dcesrv_remote.o
PUBLIC_DEPENDENCIES = \
		LIBCLI_SMB NDR_TABLE
# End MODULE dcerpc_remote
################################################

################################################
# Start MODULE dcerpc_srvsvc
[MODULE::dcerpc_srvsvc]
INIT_FUNCTION = dcerpc_server_srvsvc_init
PRIVATE_PROTO_HEADER = srvsvc/proto.h
SUBSYSTEM = dcerpc_server
OBJ_FILES = \
		srvsvc/dcesrv_srvsvc.o \
		srvsvc/srvsvc_ntvfs.o
PUBLIC_DEPENDENCIES = \
		DCERPC_COMMON NDR_SRVSVC share
# End MODULE dcerpc_srvsvc
################################################

################################################
# Start MODULE dcerpc_wkssvc
[MODULE::dcerpc_wkssvc]
INIT_FUNCTION = dcerpc_server_wkssvc_init
SUBSYSTEM = dcerpc_server
OBJ_FILES = \
		wkssvc/dcesrv_wkssvc.o
PUBLIC_DEPENDENCIES = \
		DCERPC_COMMON NDR_WKSSVC
# End MODULE dcerpc_wkssvc
################################################

################################################
# Start MODULE dcerpc_unixinfo
[MODULE::dcerpc_unixinfo]
INIT_FUNCTION = dcerpc_server_unixinfo_init
SUBSYSTEM = dcerpc_server
OBJ_FILES = \
		unixinfo/dcesrv_unixinfo.o
PUBLIC_DEPENDENCIES = \
		DCERPC_COMMON \
		SAMDB \
		NDR_UNIXINFO
# End MODULE dcerpc_unixinfo
################################################

################################################
# Start MODULE dcesrv_samr
[MODULE::dcesrv_samr]
INIT_FUNCTION = dcerpc_server_samr_init
PRIVATE_PROTO_HEADER = samr/proto.h
SUBSYSTEM = dcerpc_server
OBJ_FILES = \
		samr/dcesrv_samr.o \
		samr/samr_password.o
PUBLIC_DEPENDENCIES = \
		SAMDB \
		DCERPC_COMMON \
		NDR_SAMR
# End MODULE dcesrv_samr
################################################

################################################
# Start MODULE dcerpc_winreg
[MODULE::dcerpc_winreg]
INIT_FUNCTION = dcerpc_server_winreg_init
SUBSYSTEM = dcerpc_server
OUTPUT_TYPE = INTEGRATED
OBJ_FILES = \
		winreg/rpc_winreg.o
PUBLIC_DEPENDENCIES = \
		registry NDR_WINREG
# End MODULE dcerpc_winreg
################################################

################################################
# Start MODULE dcerpc_netlogon
[MODULE::dcerpc_netlogon]
INIT_FUNCTION = dcerpc_server_netlogon_init
SUBSYSTEM = dcerpc_server
OBJ_FILES = \
		netlogon/dcerpc_netlogon.o
PUBLIC_DEPENDENCIES = \
		DCERPC_COMMON \
		SCHANNELDB \
		NDR_NETLOGON \
		auth_sam
# End MODULE dcerpc_netlogon
################################################

################################################
# Start MODULE dcerpc_lsa
[MODULE::dcerpc_lsarpc]
INIT_FUNCTION = dcerpc_server_lsa_init
SUBSYSTEM = dcerpc_server
OBJ_FILES = \
		lsa/dcesrv_lsa.o
PUBLIC_DEPENDENCIES = \
		SAMDB \
		DCERPC_COMMON \
		NDR_LSA \
		LIBCLI_AUTH \
		NDR_DSSETUP
# End MODULE dcerpc_lsa
################################################

################################################
# Start MODULE dcerpc_spoolss
[MODULE::dcerpc_spoolss]
INIT_FUNCTION = dcerpc_server_spoolss_init
SUBSYSTEM = dcerpc_server
OUTPUT_TYPE = INTEGRATED
OBJ_FILES = \
		spoolss/dcesrv_spoolss.o
PUBLIC_DEPENDENCIES = \
		DCERPC_COMMON \
		NDR_SPOOLSS \
		ntptr
# End MODULE dcerpc_spoolss
################################################

################################################
# Start MODULE dcerpc_drsuapi
[MODULE::dcerpc_drsuapi]
INIT_FUNCTION = dcerpc_server_drsuapi_init
SUBSYSTEM = dcerpc_server
OBJ_FILES = \
		drsuapi/dcesrv_drsuapi.o
PUBLIC_DEPENDENCIES = \
		SAMDB \
		DCERPC_COMMON \
		NDR_DRSUAPI
# End MODULE dcerpc_drsuapi
################################################

################################################
# Start SUBSYSTEM dcerpc_server
[MODULE::dcerpc_server]
INIT_FUNCTION = server_service_rpc_init
SUBSYSTEM = service
PUBLIC_HEADERS = dcerpc_server.h
PUBLIC_PROTO_HEADER = dcerpc_server_proto.h
OBJ_FILES = \
		dcerpc_server.o \
		dcerpc_sock.o \
		dcesrv_auth.o \
		dcesrv_mgmt.o \
		handles.o
PUBLIC_DEPENDENCIES = \
		LIBCLI_AUTH \
		LIBNDR \
		dcerpc
#
# End SUBSYSTEM DCERPC
################################################
