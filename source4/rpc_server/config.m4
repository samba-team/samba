dnl # DCERPC Server subsystem

SMB_MODULE(dcerpc_rpcecho, DCERPC, STATIC, \$(DCERPC_RPCECHO_OBJ), "bin/dcerpc_rpcecho.$SHLIBEXT$")
SMB_MODULE(dcerpc_epmapper, DCERPC, STATIC, \$(DCERPC_EPMAPPER_OBJ), "bin/dcerpc_epmapper.$SHLIBEXT$")
SMB_MODULE(dcerpc_remote, DCERPC, STATIC, \$(DCERPC_REMOTE_OBJ), "bin/dcerpc_remote.$SHLIBEXT$")

SMB_SUBSYSTEM(DCERPC,rpc_server/dcerpc_server.o)
