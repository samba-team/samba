dnl # AUTH Server subsystem

SMB_MODULE_MK(auth_sam,AUTH,STATIC,auth/config.mk)
SMB_MODULE_MK(auth_builtin,AUTH,STATIC,auth/config.mk)

SMB_SUBSYSTEM_MK(AUTH,auth/config.mk)
