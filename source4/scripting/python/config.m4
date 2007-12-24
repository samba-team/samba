m4_include(scripting/python/ac_pkg_swig.m4)

AC_ARG_VAR([PYTHON_VERSION],[The installed Python
	version to use, for example '2.3'. This string 
	will be appended to the Python interpreter
	canonical name.])

AC_PROG_SWIG(1.3.31)

AC_PATH_PROG([PYTHON],[python[$PYTHON_VERSION]])
if test -z "$PYTHON"; then
	working_python=no
	AC_MSG_WARN([No python found])
fi

AC_PATH_PROG([PYTHON_CONFIG],[python[$PYTHON_VERSION]-config])
if test -z "$PYTHON_CONFIG"; then
	working_python=no
	AC_MSG_WARN([No python-config found])
else
	working_python=yes
fi

PYTHON_LDFLAGS=`$PYTHON_CONFIG --ldflags`
PYTHON_CFLAGS=`$PYTHON_CONFIG --cflags`

SMB_EXT_LIB(LIBPYTHON, [$PYTHON_LDFLAGS], [$PYTHON_CFLAGS])

AC_MSG_CHECKING(working python module support)
if test x$working_python = xyes
then
	ac_save_LIBS="$LIBS"
	ac_save_CFLAGS="$CFLAGS"
	LIBS="$LIBS $PYTHON_LDFLAGS"
	CFLAGS="$CFLAGS $PYTHON_CFLAGS"

	AC_TRY_LINK([
			#include <Python.h>
			#include <stdlib.h>
		],[
			Py_InitModule(NULL, NULL);
		],[
			SMB_ENABLE(LIBPYTHON,YES)
			SMB_ENABLE(smbpython,YES)
			AC_MSG_RESULT([yes])
		],[
			SMB_ENABLE(LIBPYTHON,NO)
			SMB_ENABLE(smbpython,NO)
			AC_MSG_RESULT([no])
		])

	LIBS="$ac_save_LIBS"
	CFLAGS="$ac_save_CFLAGS"
else
	SMB_ENABLE(LIBPYTHON,NO)
	SMB_ENABLE(smbpython,NO)
	AC_MSG_RESULT([no])
fi
