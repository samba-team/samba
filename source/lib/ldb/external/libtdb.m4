m4_include(pkg.m4)
TDB_OBJ=""
AC_SUBST(TDB_OBJ)
PKG_CHECK_MODULES(TDB, tdb >= 1.1.0)
