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

if test -z "$PYTHON_VERSION"; then 
	AC_PATH_PROGS([PYTHON_CONFIG], [python2.6-config python2.5-config python2.4-config python-config])
else 
	AC_PATH_PROG([PYTHON_CONFIG], [python[$PYTHON_VERSION]-config])
fi

if test -z "$PYTHON_CONFIG"; then
	working_python=no
	AC_MSG_WARN([No python-config found])
else
	working_python=yes
	PYTHON_LDFLAGS=`$PYTHON_CONFIG --ldflags`
	PYTHON_CFLAGS=`$PYTHON_CONFIG --cflags`
fi

if test $working_python = no && test x$PYTHON != x
then
	PYTHON_CFLAGS=`$PYTHON -c "from distutils import sysconfig; print '-I%s -I%s %s' % (sysconfig.get_python_inc(), sysconfig.get_python_inc(plat_specific=True), sysconfig.get_config_var('CFLAGS'))"`
	PYTHON_LDFLAGS=`$PYTHON -c "from distutils import sysconfig; print '%s %s -lpython%s -L%s' % (sysconfig.get_config_var('LIBS'), sysconfig.get_config_var('SYSLIBS'), sysconfig.get_config_var('VERSION'), sysconfig.get_config_var('LIBPL'))"`
	working_python=yes
fi

SMB_EXT_LIB(EXT_LIB_PYTHON, [$PYTHON_LDFLAGS], [$PYTHON_CFLAGS])

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
			SMB_ENABLE(EXT_LIB_PYTHON,YES)
			SMB_ENABLE(smbpython,YES)
			SMB_ENABLE(LIBPYTHON,YES)
			AC_MSG_RESULT([yes])
		],[
			SMB_ENABLE(EXT_LIB_PYTHON,NO)
			SMB_ENABLE(LIBPYTHON,NO)
			SMB_ENABLE(smbpython,NO)
			AC_MSG_RESULT([no])
		])

	LIBS="$ac_save_LIBS"
	CFLAGS="$ac_save_CFLAGS"
else
	SMB_ENABLE(EXT_LIB_PYTHON,NO)
	SMB_ENABLE(LIBPYTHONyy,NO)
	SMB_ENABLE(smbpython,NO)
	AC_MSG_RESULT([no])
fi
