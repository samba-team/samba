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
		;;
esac
AC_SUBST(PICFLAG)
])

AC_DEFUN([AC_LD_SHLDFLAGS],
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
			SHLD_FLAGS="-set_version sgi1.0 -shared"
			;;
		*aix*)
			SHLD_FLAGS="-Wl,-G,-bexpall,-bbigtoc"
			;;
		*hpux*)
			if test $ac_cv_prog_cc_Ae = yes; then
				SHLD_FLAGS="-b -Wl,-B,symbolic,-b,-z"
			fi
			;;
		*darwin*)
			SHLD_FLAGS="-bundle -flat_namespace -undefined suppress"
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
