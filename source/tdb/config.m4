AC_CHECK_FUNCS(mmap pread pwrite getpagesize utime)
AC_CHECK_HEADERS(getopt.h sys/select.h sys/time.h)

AC_HAVE_DECL(pread, [#include <unistd.h>])
AC_HAVE_DECL(pwrite, [#include <unistd.h>])

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
	SMB_ENABLE(swig_tdb, NO)
	AC_MSG_RESULT(no)
fi

AC_SUBST(PYTHON)
