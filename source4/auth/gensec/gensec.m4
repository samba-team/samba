SMB_MODULE_DEFAULT(gensec_krb5, NOT)
SMB_MODULE_DEFAULT(gensec_gssapi, NOT)
SMB_MODULE_DEFAULT(gensec_gsskrb5, NOT)

if test x"$SMB_EXT_LIB_ENABLE_KRB5" = x"YES"; then
	# krb5 is now disabled at runtime, not build time
	SMB_MODULE_DEFAULT(gensec_krb5, STATIC)
	SMB_MODULE_DEFAULT(gensec_gssapi, STATIC)
	if test x"$samba_cv_GSS_C_DCE_STYLE" = x"yes"; then
		SMB_MODULE_DEFAULT(gensec_gsskrb5, STATIC)
	fi
fi
