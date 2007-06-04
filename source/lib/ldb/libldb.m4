SMB_ENABLE(ldb_sqlite3,$with_sqlite3_support)

AC_MSG_CHECKING([for Python])

PYTHON=
 
AC_ARG_WITH(python,
[  --with-python=PYTHONNAME  build Python libraries],
[ case "${withval-python}" in
  yes)
        PYTHON=python
        ;;
  no)
        PYTHON=
        ;;
  *)
        PYTHON=${withval-python}
        ;;
  esac ])

if test x"$PYTHON" != "x"; then
	incdir=`python -c 'import sys; print "%s/include/python%d.%d" % (sys.prefix, sys.version_info[[0]], sys.version_info[[1]])'`
	CPPFLAGS="$CPPFLAGS -I $incdir"
fi

if test x"$PYTHON" != "x"; then
	AC_MSG_RESULT([${withval-python}])
else
	AC_MSG_RESULT(no)
	SMB_ENABLE(swig_ldb, NO)
fi

AC_SUBST(PYTHON)
