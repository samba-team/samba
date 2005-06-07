SMB_MODULE_DEFAULT(server_service_kdc, NOT)

if test t$HAVE_KRB5 = tYES; then
	SMB_MODULE_DEFAULT(server_service_kdc, STATIC)
fi
