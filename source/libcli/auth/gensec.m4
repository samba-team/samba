SMB_MODULE_DEFAULT(gensec_krb5, NOT)
SMB_MODULE_DEFAULT(gensec_gssapi, NOT)

if test x"$SMB_EXT_LIB_ENABLE_KRB5" = x"YES"; then
	/* enable this when krb5 is fully working */
	SMB_MODULE_DEFAULT(gensec_krb5, STATIC)
	SMB_MODULE_DEFAULT(gensec_gssapi, STATIC)
fi
