dnl $Id$
dnl
dnl CHECK_COMPILE_ET
AC_DEFUN([CHECK_COMPILE_ET], [

AC_CHECK_PROG(COMPILE_ET, compile_et, [compile_et])

krb_cv_compile_et="no"
if test "${COMPILE_ET}" = "compile_et"; then

dnl We have compile_et.  Now let's see if it supports `prefix' and `index'.
AC_MSG_CHECKING(compile_et features)
cat > conftest.et <<'EOF'
error_table conf
prefix CONFTEST
error_code CODE1, "CODE1"
index 128
error_code CODE2, "CODE2"
end
EOF
if ${COMPILE_ET} conftest.et >/dev/null 2>&1; then
	AC_MSG_RESULT(enough)
        krb_cv_compile_et="yes"
else
	AC_MSG_RESULT(insufficient)
fi
rm -fr conftest*
fi

AC_CHECK_LIB(com_err, error_message,
  [krb_cv_com_err="yes"],
  [krb_cv_com_err="no"])

dnl Only use the system's compile_et or libcom_err if we have them both.
if test "${krb_cv_compile_et}" = "yes" && \
   test "${krb_cv_com_err}" = "yes"; then
    DIR_com_err=""
    LIB_com_err="-lcom_err"
    LIB_com_err_a=""
    LIB_com_err_so=""
else
    COMPILE_ET="\$(top_builddir)/lib/com_err_compile_et"
    DIR_com_err="com_err"
    LIB_com_err="\$(top_builddir)/lib/com_err/libcom_err.la"
    LIB_com_err_a="\$(top_builddir)/lib/com_err/.libs/libcom_err.a"
    LIB_com_err_so="\$(top_builddir)/lib/com_err/.libs/libcom_err.so"
fi
AC_SUBST(DIR_com_err)
AC_SUBST(LIB_com_err)
AC_SUBST(LIB_com_err_a)
AC_SUBST(LIB_com_err_so)

])
