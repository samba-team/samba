#################################################
# Check if the user wants Python

# At the moment, you can use this to set which Python binary to link
# against.  (Libraries built for Python2.2 can't be used by 2.1,
# though they can coexist in different directories.)  In the future
# this might make the Python stuff be built by default.

# Defaulting python breaks the clean target if python isn't installed

PYTHON=

AC_ARG_WITH(python,
[  --with-python=PYTHONNAME  build Python libraries],
[ case "${withval-python}" in
  yes)
	PYTHON=python
	EXTRA_ALL_TARGETS="$EXTRA_ALL_TARGETS python_ext"
	;;
  no)
	PYTHON=
	;;
  *)
	PYTHON=${withval-python}
	;;
  esac ])
AC_SUBST(PYTHON)
