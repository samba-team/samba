if test x"$SMB_EXT_LIB_ENABLE_KRB5" = x"YES"; then
	/* enable this when krb5 is fully working */
	SMB_MODULE_DEFAULT(gensec_krb5, NOT)
fi
