if test x"$with_ldap_support" = x"yes"; then
    SMB_MODULE_DEFAULT(libldb_ldap,STATIC)
fi

if test x"$experimental" = x"yes"; then
	SMB_LIBRARY_ENABLE(libldb,YES)
fi
