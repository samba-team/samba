SMB_MODULE_DEFAULT(libldb_ldap,NOT)
if test x"$with_ldap_support" = x"yes"; then
    SMB_MODULE_DEFAULT(libldb_ldap,STATIC)
fi

SMB_LIBRARY_ENABLE(libldb,NO)
if test x"$experimental" = x"yes"; then
	SMB_LIBRARY_ENABLE(libldb,YES)
fi
