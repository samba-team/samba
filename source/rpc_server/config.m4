dnl # DCERPC Server subsystem

SMB_SUBSYSTEM_MK(DCERPC_COMMON,rpc_server/config.mk)

SMB_SUBSYSTEM_MK(SAMDB,rpc_server/config.mk)
SMB_SUBSYSTEM_MK(SCHANNELDB,rpc_server/config.mk)

SMB_MODULE_MK(dcerpc_rpcecho,DCERPC,STATIC,rpc_server/config.mk)
SMB_MODULE_MK(dcerpc_epmapper,DCERPC,STATIC,rpc_server/config.mk)
SMB_MODULE_MK(dcerpc_remote,DCERPC,STATIC,rpc_server/config.mk)
SMB_MODULE_MK(dcerpc_srvsvc,DCERPC,STATIC,rpc_server/config.mk)
SMB_MODULE_MK(dcerpc_wkssvc,DCERPC,STATIC,rpc_server/config.mk)
SMB_MODULE_MK(dcerpc_samr,DCERPC,STATIC,rpc_server/config.mk)
SMB_MODULE_MK(dcerpc_winreg,DCERPC,STATIC,rpc_server/config.mk)
SMB_MODULE_MK(dcerpc_netlogon,DCERPC,STATIC,rpc_server/config.mk)
SMB_MODULE_MK(dcerpc_lsarpc,DCERPC,STATIC,rpc_server/config.mk)
SMB_MODULE_MK(dcerpc_spoolss,DCERPC,STATIC,rpc_server/config.mk)
SMB_MODULE_MK(dcerpc_IOXIDResolver,DCERPC,STATIC,rpc_server/config.mk)
SMB_MODULE_MK(dcerpc_drsuapi,DCERPC,STATIC,rpc_server/config.mk)

SMB_SUBSYSTEM_MK(DCERPC,rpc_server/config.mk)
