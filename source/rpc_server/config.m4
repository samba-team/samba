dnl # DCERPC Server subsystem

SMB_SUBSYSTEM(DCERPC_COMMON,[],
		[rpc_server/common/server_info.o
		rpc_server/common/share_info.o])

SMB_SUBSYSTEM(SAMDB,[rpc_server/samr/samdb.o],[],[],[LIBLDB])

SMB_MODULE(dcerpc_rpcecho,DCERPC,STATIC,[rpc_server/echo/rpc_echo.o])
SMB_MODULE(dcerpc_epmapper,DCERPC,STATIC,[rpc_server/epmapper/rpc_epmapper.o])
SMB_MODULE(dcerpc_remote,DCERPC,STATIC,[rpc_server/remote/dcesrv_remote.o],[],[],[LIBSMB])
SMB_MODULE(dcerpc_srvsvc,DCERPC,STATIC,[rpc_server/srvsvc/dcesrv_srvsvc.o],[],[],[DCERPC_COMMON])
SMB_MODULE(dcerpc_wkssvc,DCERPC,STATIC,[rpc_server/wkssvc/dcesrv_wkssvc.o],[],[],[DCERPC_COMMON])
SMB_MODULE(dcerpc_samr,DCERPC,STATIC,[rpc_server/samr/dcesrv_samr.o],[],[],[SAMDB DCERPC_COMMON])
SMB_MODULE(dcerpc_winreg,DCERPC,STATIC,[rpc_server/winreg/rpc_winreg.o],[],[],[REGISTRY])

SMB_SUBSYSTEM(DCERPC,rpc_server/dcerpc_server.o,
		[rpc_server/dcerpc_tcp.o
		rpc_server/dcesrv_auth.o
		rpc_server/handles.o])
