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

AC_DEFUN([TRY_LINK_PYTHON],
[
	if test $working_python = no; then
		ac_save_LIBS="$LIBS"
		ac_save_CFLAGS="$CFLAGS"
		LIBS="$LIBS $1"
		CFLAGS="$CFLAGS $2"

		AC_TRY_LINK([
				/* we have our own configure tests */
				#include <Python.h>
			],[
				Py_InitModule(NULL, NULL);
			],[
				PYTHON_LDFLAGS="$1"
				PYTHON_CFLAGS="$2"
				working_python=yes
			])
		LIBS="$ac_save_LIBS"
		CFLAGS="$ac_save_CFLAGS"
	fi
])

dnl assume no working python
working_python=no

if test -z "$PYTHON_VERSION"; then 
	AC_PATH_PROGS([PYTHON_CONFIG], [python2.6-config python2.5-config python2.4-config python-config])
else 
	AC_PATH_PROG([PYTHON_CONFIG], [python[$PYTHON_VERSION]-config])
fi

if test -z "$PYTHON_CONFIG"; then
	AC_MSG_WARN([No python-config found])
else
	TRY_LINK_PYTHON([`$PYTHON_CONFIG --ldflags`], [`$PYTHON_CONFIG --includes`])
	TRY_LINK_PYTHON([`$PYTHON_CONFIG --ldflags`], [`$PYTHON_CONFIG --cflags`])
fi

if test x$PYTHON != x
then
	DISTUTILS_CFLAGS=`$PYTHON -c "from distutils import sysconfig; print '-I%s -I%s %s' % (sysconfig.get_python_inc(), sysconfig.get_python_inc(plat_specific=1), sysconfig.get_config_var('CFLAGS'))"`
	DISTUTILS_LDFLAGS=`$PYTHON -c "from distutils import sysconfig; print '%s %s -lpython%s -L%s' % (sysconfig.get_config_var('LIBS'), sysconfig.get_config_var('SYSLIBS'), sysconfig.get_config_var('VERSION'), sysconfig.get_config_var('LIBPL'))"`
	TRY_LINK_PYTHON($DISTUTILS_LDFLAGS, $DISTUTILS_CFLAGS)
fi

SMB_EXT_LIB(EXT_LIB_PYTHON, [$PYTHON_LDFLAGS], [$PYTHON_CFLAGS])

AC_MSG_CHECKING(working python module support)
if test $working_python = yes; then
	SMB_ENABLE(EXT_LIB_PYTHON,YES)
	SMB_ENABLE(smbpython,YES)
	SMB_ENABLE(LIBPYTHON,YES)
	AC_MSG_RESULT([yes])
else
	AC_MSG_ERROR([Python not found. Please install Python 2.x and its development headers/libraries.])
fi

