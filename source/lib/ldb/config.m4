SMB_MODULE_DEFAULT(libldb_ldap,NOT)
if test x"$with_ldap_support" = x"yes"; then
    SMB_MODULE_DEFAULT(libldb_ldap,STATIC)
fi

SMB_MODULE_DEFAULT(libldb_sqlite3,NOT)
if test x"$with_sqlite3_support" = x"yes"; then
    SMB_MODULE_DEFAULT(libldb_sqlite3,STATIC)
fi

SMB_LIBRARY_ENABLE(libldb,NO)
if test x"$experimental" = x"yes"; then
	SMB_LIBRARY_ENABLE(libldb,YES)
fi
