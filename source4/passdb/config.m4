########################################################
# Compile with MySQL support?
AM_PATH_MYSQL([0.11.0],[MODULE_MYSQL=bin/mysql.so],[MODULE_MYSQL=])
CFLAGS="$CFLAGS $MYSQL_CFLAGS"
AC_SUBST(MODULE_MYSQL)

########################################################
# Compile with XML support?
AM_PATH_XML2([2.0.0],[MODULE_XML=bin/xml.so],[MODULE_XML=])
CFLAGS="$CFLAGS $XML_CFLAGS"
AC_SUBST(MODULE_XML)
