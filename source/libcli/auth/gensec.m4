if test t$SMB_EXT_LIB_ENABLE_KRB5 = tYES; then
	SMB_MODULE_DEFAULT(gensec_krb5, STATIC)
fi

SMB_SUBSYSTEM_MK(GENSEC,libcli/auth/gensec.mk)
SMB_MODULE_MK(gensec_krb5, GENSEC, NOT, libcli/auth/gensec.mk)
SMB_MODULE_MK(gensec_ntlmssp, GENSEC, STATIC, libcli/auth/gensec.mk)
SMB_MODULE_MK(gensec_spnego, GENSEC, STATIC, libcli/auth/gensec.mk)
