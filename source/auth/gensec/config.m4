SMB_MODULE_DEFAULT(gensec_krb5, NOT)
SMB_MODULE_DEFAULT(gensec_gssapi, NOT)

if test x"$HAVE_KRB5" = x"YES"; then
	# krb5 is now disabled at runtime, not build time
	SMB_MODULE_DEFAULT(gensec_krb5, STATIC)
	SMB_MODULE_DEFAULT(gensec_gssapi, STATIC)
fi
