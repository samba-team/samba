dnl # DCERPC Server subsystem

SMB_MODULE(dcerpc_rpcecho, STATIC, \$(DCERPC_RPCECHO_OBJ), "bin/dcerpc_rpcecho.$SHLIBEXT$", DCERPC)
SMB_MODULE(dcerpc_epmapper, STATIC, \$(DCERPC_EPMAPPER_OBJ), "bin/dcerpc_epmapper.$SHLIBEXT$", DCERPC)
SMB_MODULE(dcerpc_remote, STATIC, \$(DCERPC_REMOTE_OBJ), "bin/dcerpc_remote.$SHLIBEXT$", DCERPC)

SMB_SUBSYSTEM(DCERPC,rpc_server/dcerpc_server.o)
