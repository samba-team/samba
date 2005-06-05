SMB_MODULE_DEFAULT(server_service_kdc, NOT)

if test t$SMB_EXT_LIB_ENABLE_KDC = tYES; then
	SMB_MODULE_DEFAULT(server_service_kdc, STATIC)
fi
