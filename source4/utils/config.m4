dnl # utils subsystem

SMB_BINARY_MK(ndrdump, utils/config.mk)
SMB_BINARY_MK(ntlm_auth, utils/config.mk)
#SMB_BINARY_MK(lookupuuid, utils/config.mk)

SMB_INCLUDE_M4(utils/net/config.m4)

SMB_BINARY_MK(getntacl, utils/config.mk)
SMB_BINARY_MK(setntacl, utils/config.mk)

SMB_BINARY_MK(setnttoken, utils/config.mk)
