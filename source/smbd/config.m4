dnl # SMB server subsystem

SMB_MODULE_MK(server_smb,SERVER,STATIC,smbd/config.mk)
SMB_MODULE_MK(server_rpc,SERVER,STATIC,smbd/config.mk)
SMB_MODULE_MK(server_auth,SERVER,STATIC,smbd/config.mk)

SMB_SUBSYSTEM_MK(SERVER,smbd/config.mk)

SMB_BINARY_MK(smbd, smbd/config.mk)
