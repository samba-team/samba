SMB_SUBSYSTEM_MK(GENSEC,libcli/auth/gensec.mk)
SMB_MODULE_MK(gensec_krb5, GENSEC, NOT, libcli/auth/gensec.mk)
SMB_MODULE_MK(gensec_ntlmssp, GENSEC, STATIC, libcli/auth/gensec.mk)
SMB_MODULE_MK(gensec_spnego, GENSEC, STATIC, libcli/auth/gensec.mk)

