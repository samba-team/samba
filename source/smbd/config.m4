dnl # server subsystem

SMB_MODULE_MK(server_service_auth,SERVER_SERVICE,STATIC,smbd/config.mk)
SMB_MODULE_MK(server_service_smb,SERVER_SERVICE,STATIC,smbd/config.mk)
SMB_MODULE_MK(server_service_rpc,SERVER_SERVICE,STATIC,smbd/config.mk)
SMB_MODULE_MK(server_service_ldap,SERVER_SERVICE,STATIC,smbd/config.mk)

SMB_SUBSYSTEM_MK(SERVER_SERVICE,smbd/config.mk)
SMB_SUBSYSTEM_MK(SERVER,smbd/config.mk)

SMB_BINARY_MK(smbd, smbd/config.mk)
