m4_include(scripting/python/ac_pkg_swig.m4)

AC_ARG_VAR([PYTHON_VERSION],[The installed Python
	version to use, for example '2.3'. This string 
	will be appended to the Python interpreter
	canonical name.])

AC_PROG_SWIG(1.3.25)

AC_PATH_PROG([PYTHON],[python[$PYTHON_VERSION]])
if test -z "$PYTHON"; then
	working_python=no
	AC_MSG_WARN([No python found])
fi

#
# Check for a version of Python >= 2.1.0
#
AC_MSG_CHECKING([for a version of Python >= '2.1.0'])
ac_supports_python_ver=`$PYTHON -c "import sys, string; \
	ver = string.split(sys.version)[[0]]; \
	print ver >= '2.1.0'"`
if test "$ac_supports_python_ver" != "True"; then
	working_python=no
	AC_MSG_RESULT([no])
else 
	AC_MSG_RESULT([yes])
fi

#
# Check if you have distutils, else fail
#
AC_MSG_CHECKING([for the distutils Python package])
ac_distutils_result=`$PYTHON -c "import distutils" 2>&1`
if test -z "$ac_distutils_result"; then
	AC_MSG_RESULT([yes])
	working_python=yes
else
	AC_MSG_RESULT([no])
	working_python=no
fi

#
# Check for Python include path
#
AC_MSG_CHECKING([for Python include path])
if test -z "$PYTHON_CPPFLAGS"; then
	python_path=`$PYTHON -c "import distutils.sysconfig; \
			print distutils.sysconfig.get_python_inc();"`
	if test -n "${python_path}"; then
		python_path="-I$python_path"
	fi
	PYTHON_CPPFLAGS=$python_path
fi
AC_MSG_RESULT([$PYTHON_CPPFLAGS])
AC_SUBST([PYTHON_CPPFLAGS])

#
# Check for Python library path
#
AC_MSG_CHECKING([for Python library path])
if test -z "$PYTHON_LDFLAGS"; then
	# (makes two attempts to ensure we've got a version number
	# from the interpreter)
	py_version=`$PYTHON -c "from distutils.sysconfig import *; \
		from string import join; \
		print join(get_config_vars('VERSION'))"`
	if test "$py_version" == "[None]"; then
		if test -n "$PYTHON_VERSION"; then
			py_version=$PYTHON_VERSION
		else
			py_version=`$PYTHON -c "import sys; \
				print sys.version[[:3]]"`
		fi
	fi

	PYTHON_LDFLAGS=`$PYTHON -c "from distutils.sysconfig import *; \
		from string import join; \
		print '-L' + get_python_lib(0,1), \
			'-lpython';"`$py_version
fi		
AC_MSG_RESULT([$PYTHON_LDFLAGS])
AC_SUBST([PYTHON_LDFLAGS])

#
# Check for site packages
#
AC_MSG_CHECKING([for Python site-packages path])
if test -z "$PYTHON_SITE_PKG"; then
	PYTHON_SITE_PKG=`$PYTHON -c "import distutils.sysconfig; \
			print distutils.sysconfig.get_python_lib(0,0);"`
fi
AC_MSG_RESULT([$PYTHON_SITE_PKG])
AC_SUBST([PYTHON_SITE_PKG])

#
# libraries which must be linked in when embedding
#
AC_MSG_CHECKING(python extra libraries)
if test -z "$PYTHON_EXTRA_LIBS"; then
   PYTHON_EXTRA_LIBS=`$PYTHON -c "import distutils.sysconfig; \
			conf = distutils.sysconfig.get_config_var; \
			print conf('LOCALMODLIBS'), conf('LIBS')"`
fi
AC_MSG_RESULT([$PYTHON_EXTRA_LIBS])
AC_SUBST(PYTHON_EXTRA_LIBS)

#
# linking flags needed when embedding
#
AC_MSG_CHECKING(python extra linking flags)
if test -z "$PYTHON_EXTRA_LDFLAGS"; then
	PYTHON_EXTRA_LDFLAGS=`$PYTHON -c "import distutils.sysconfig; \
		conf = distutils.sysconfig.get_config_var; \
		print conf('LINKFORSHARED')"`
fi
AC_MSG_RESULT([$PYTHON_EXTRA_LDFLAGS])
AC_SUBST(PYTHON_EXTRA_LDFLAGS)

SMB_EXT_LIB(LIBPYTHON, [$PYTHON_LDFLAGS], [$PYTHON_CPPFLAGS])

if test x$working_python = xyes
then
	SMB_ENABLE(LIBPYTHON,YES)
else
	SMB_ENABLE(LIBPYTHON,NO)
fi
