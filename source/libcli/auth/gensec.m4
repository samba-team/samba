if test x"$SMB_EXT_LIB_ENABLE_KRB5" = x"YES"; then
	/* enable this when krb5 is fully working */
	SMB_MODULE_DEFAULT(gensec_krb5, NOT)
fi

SMB_SUBSYSTEM_MK(GENSEC,libcli/auth/gensec.mk)
SMB_MODULE_MK(gensec_krb5, GENSEC, NOT, libcli/auth/gensec.mk)
SMB_MODULE_MK(gensec_ntlmssp, GENSEC, STATIC, libcli/auth/gensec.mk)
SMB_MODULE_MK(gensec_spnego, GENSEC, STATIC, libcli/auth/gensec.mk)
