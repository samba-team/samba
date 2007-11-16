#
# This offers a nice overview how to build shared libraries on all platforms
#        http://www.fortran-2000.com/ArnaudRecipes/sharedlib.html
#

AC_DEFUN([AC_LIBREPLACE_STLD],
[
	AC_PATH_PROG(PROG_AR, ar)

	STLD=${PROG_AR}

	AC_SUBST(STLD)
])

AC_DEFUN([AC_LIBREPLACE_STLD_FLAGS],
[
	STLD_FLAGS="-rcs"
	AC_SUBST(STLD_FLAGS)
])

AC_DEFUN([AC_LD_EXPORT_DYNAMIC],
[
saved_LDFLAGS="$LDFLAGS"
if AC_TRY_COMMAND([${CC-cc} $CFLAGS -Wl,--version 2>&1 | grep "GNU ld" >/dev/null]); then
	LD_EXPORT_DYNAMIC="-Wl,-export-dynamic"
else
	case "$host_os" in
		hpux* )
		  LD_EXPORT_DYNAMIC="-Wl,-E"
		  ;;
		*)
		  LD_EXPORT_DYNAMIC=""
		  ;;
	  esac
fi
AC_SUBST(LD_EXPORT_DYNAMIC)
LDFLAGS="$saved_LDFLAGS"
])

AC_DEFUN([AC_LD_PICFLAG],
[
case "$host_os" in
	*linux*) 
		PICFLAG="-fPIC" 
		;;
	*solaris*)
		if test "${GCC}" = "yes"; then
			PICFLAG="-fPIC"
		else
			PICFLAG="-KPIC"
		fi
		;;
	*sunos*)
		PICFLAG="-KPIC"   # Is this correct for SunOS
		;;
	*netbsd* | *freebsd* | *dragonfly* )  
		PICFLAG="-fPIC -DPIC"
		;;
	*openbsd*)
		PICFLAG="-fPIC"
		;;
	*irix*)
		if test "${GCC}" = "yes"; then
			PICFLAG="-fPIC"
		else 
			PICFLAG="-KPIC"
		fi
		;;
	*aix*)
		# as AIX code is always position independent...
		PICFLAG="-O2"
		;;
	*hpux*)
		if test $ac_cv_prog_cc_Ae = yes; then
			PICFLAG="+z +ESnolit"
		elif test "${GCC}" = "yes"; then
			PICFLAG="-fPIC"
		fi
		if test "$host_cpu" = "ia64"; then
			PICFLAG="+z"
		fi
		;;
	*osf*)
		PICFLAG="-fPIC"
		;;
	*unixware*)
		PICFLAG="-KPIC"
		;;
	*darwin*)
		PICFLAG="-fno-common"
		;;
esac
AC_SUBST(PICFLAG)
])

AC_DEFUN([AC_LIBREPLACE_SHLD],
[
	SHLD="${CC}"

	case "$host_os" in
		*irix*)
			SHLD="${PROG_LD}"
			;;
	esac

	AC_SUBST(SHLD)
])

AC_DEFUN([AC_LIBREPLACE_SHLD_FLAGS],
[
	SHLD_FLAGS="-shared"

	case "$host_os" in
		*linux*)
			SHLD_FLAGS="-shared -Wl,-Bsymbolic"
			;;
		*solaris*)
			SHLD_FLAGS="-G"
			if test "${GCC}" = "no"; then
				## ${CFLAGS} added for building 64-bit shared 
				## libs using Sun's Compiler
				SHLD_FLAGS="-G \${CFLAGS}"
			fi
			;;
		*sunos*)
			SHLD_FLAGS="-G"
			;;
		*irix*)
			SHLD_FLAGS="-shared"
			;;
		*aix*)
			SHLD_FLAGS="-Wl,-G,-bexpall,-bbigtoc"
			;;
		*hpux*)
			if test "${GCC}" = "yes"; then
				SHLD_FLAGS="-shared"
			else
				SHLD_FLAGS="-b"
			fi
			;;
		*osf*)
			SHLD_FLAGS="-shared -warning_unresolved"
			;;
		*darwin*)
			SHLD_FLAGS="-bundle -flat_namespace -undefined warning -Wl,-search_paths_first"
			;;
	esac

	AC_SUBST(SHLD_FLAGS)
])

AC_DEFUN([AC_LD_SHLIBEXT],
[
	SHLIBEXT="so"
	case "$host_os" in
		*hpux*)
			if test "$host_cpu" = "ia64"; then
				SHLIBEXT="so"
			else
				SHLIBEXT="sl"
			fi
		;;
		*darwin*)
			SHLIBEXT="dylib"
		;;
	esac
	AC_SUBST(SHLIBEXT)
])

AC_DEFUN([AC_LD_SONAMEFLAG],
[
	AC_SUBST(SONAMEFLAG)
	SONAMEFLAG=""
	case "$host_os" in 
		*linux*)
			SONAMEFLAG="-Wl,-soname="
			;;
		*solaris*)
			SONAMEFLAG="-h "
			if test "${GCC}" = "yes"; then
				SONAMEFLAG="-Wl,-soname="
			fi
			;;
		*sunos*)
			SONAMEFLAG="-Wl,-h,"
			;;
		*netbsd* | *freebsd* | *dragonfly* )
			SONAMEFLAG="-Wl,-soname,"
			;;
		*openbsd*)
			SONAMEFLAG="-Wl,-soname,"
			;;
		*irix*)
			SONAMEFLAG="-Wl,-soname,"
			;;
		*hpux*)
			SONAMEFLAG="-Wl,+h,"
			;;
		*osf*)
			SONAMEFLAG="-Wl,-soname,"
			;;
		*unixware*)
			SONAMEFLAG="-Wl,-soname,"
			;;
		*darwin*)
			SONAMEFLAG="#"
			;;
		*aix*)
			# Not supported
			SONAMEFLAG="#"
			;;
		esac
])

AC_DEFUN([AC_LIBREPLACE_MDLD],
[
	AC_LIBREPLACE_SHLD()
	MDLD=$SHLD
	AC_SUBST(MDLD)
])

AC_DEFUN([AC_LIBREPLACE_LD_ALLOW_SHLIB_UNDEF_FLAG],
[
	case "$host_os" in
		*linux*)
			SHLD_ALLOW_SHLIB_UNDEF_FLAG="-Wl,--allow-shlib-undefined"
			;;
		*osf*)
			SHLD_ALLOW_SHLIB_UNDEF_FLAG="-expect_unresolved '*'"
			;;
		*darwin*)
			SHLD_ALLOW_SHLIB_UNDEF_FLAG="-undefined suppress"
			;;
		esac
		AC_SUBST(SHLD_ALLOW_SHLIB_UNDEF_FLAG)
])

AC_DEFUN([AC_LIBREPLACE_MDLD_FLAGS],
[
	AC_LIBREPLACE_SHLD_FLAGS()
	AC_LIBREPLACE_LD_ALLOW_SHLIB_UNDEF_FLAG()
	MDLD_FLAGS="$SHLD_FLAGS $SHLD_ALLOW_SHLIB_UNDEF_FLAG"
	AC_SUBST(MDLD_FLAGS)
])

AC_DEFUN([AC_LIBREPLACE_RUNTIME_LIB_PATH_VAR],
[
	case "$host_os" in
		*linux*)
			LIB_PATH_VAR=LD_LIBRARY_PATH
		;;
		*solaris*)
			LIB_PATH_VAR=LD_LIBRARY_PATH
		;;
		*hpux*)
			LIB_PATH_VAR=SHLIB_PATH
		;;
		*osf*)
			LIB_PATH_VAR=LD_LIBRARY_PATH
		;;
		*aix*)
			LIB_PATH_VAR=LIB_PATH
			;;
		*irix*)
			LIB_PATH_VAR=LD_LIBRARY_PATH
			;;
		*darwin*)
			LIB_PATH_VAR=DYLD_LIBRARY_PATH
			;;
	esac

	AC_SUBST(LIB_PATH_VAR)
])
