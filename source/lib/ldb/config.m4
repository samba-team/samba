SMB_MODULE_DEFAULT(libldb_sqlite3,NOT)
if test x"$with_sqlite3_support" = x"yes"; then
    SMB_MODULE_DEFAULT(libldb_sqlite3,STATIC)
fi
