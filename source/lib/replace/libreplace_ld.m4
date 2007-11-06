AC_DEFUN([AC_LD_EXPORT_DYNAMIC],
[
saved_LDFLAGS="$LDFLAGS"
LDFLAGS="$LDFLAGS -Wl,--export-dynamic"
AC_LINK_IFELSE([ int main() { return 0; } ],
[ LD_EXPORT_DYNAMIC=-Wl,--export-dynamic  ],
[ LD_EXPORT_DYNAMIC= ])
AC_SUBST(LD_EXPORT_DYNAMIC)
LDFLAGS="$saved_LDFLAGS"
])
