default_static_modules="$default_static_modules dcerpc_rpcecho dcerpc_epmapper dcerpc_remote"

SMB_MODULE(dcerpc_rpcecho, \$(DCERPC_RPCECHO_OBJ), "bin/dcerpc_rpcecho.$SHLIBEXT$", DCERPC)
SMB_MODULE(dcerpc_epmapper, \$(DCERPC_EPMAPPER_OBJ), "bin/dcerpc_epmapper.$SHLIBEXT$", DCERPC)
SMB_MODULE(dcerpc_remote, \$(DCERPC_REMOTE_OBJ), "bin/dcerpc_remote.$SHLIBEXT$", DCERPC)

SMB_SUBSYSTEM(DCERPC,rpc_server/dcerpc_server.o)
