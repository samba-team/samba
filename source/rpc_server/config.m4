dnl # DCERPC Server subsystem

SMB_MODULE(dcerpc_rpcecho,DCERPC,STATIC,[rpc_server/echo/rpc_echo.o])
SMB_MODULE(dcerpc_epmapper,DCERPC,STATIC,[rpc_server/epmapper/rpc_epmapper.o])
SMB_MODULE(dcerpc_remote,DCERPC,STATIC,[rpc_server/remote/dcesrv_remote.o])

SMB_SUBSYSTEM(DCERPC,rpc_server/dcerpc_server.o,
		[rpc_server/dcerpc_tcp.o rpc_server/dcesrv_auth.o rpc_server/handles.o],
		rpc_server/dcesrv_public_proto.h)
