if test x"$with_ldap_support" = x"yes"; then
    SMB_MODULE_DEFAULT(libldb_ldap,STATIC)
fi

SMB_MODULE_MK(libldb_ldap,LIBLDB,NOT,lib/ldb/config.mk)

SMB_MODULE_MK(libldb_tdb,LIBLDB,STATIC,lib/ldb/config.mk)

SMB_SUBSYSTEM_MK(LIBLDB,lib/ldb/config.mk)

if test x"$experimental" = x"yes"; then
	SMB_LIBRARY_ENABLE(libldb,YES)
fi

SMB_LIBRARY_MK(libldb,lib/ldb/config.mk)

SMB_BINARY_MK(ldbadd,lib/ldb/config.mk)

SMB_BINARY_MK(ldbdel,lib/ldb/config.mk)

SMB_BINARY_MK(ldbmodify,lib/ldb/config.mk)

SMB_BINARY_MK(ldbsearch,lib/ldb/config.mk)

SMB_BINARY_MK(ldbedit,lib/ldb/config.mk)
