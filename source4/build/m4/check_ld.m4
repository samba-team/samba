dnl SMB Build Environment LD Checks
dnl -------------------------------------------------------
dnl  Copyright (C) Stefan (metze) Metzmacher 2004
dnl  Copyright (C) Jelmer Vernooij 2006
dnl  Released under the GNU GPL
dnl -------------------------------------------------------
dnl

AC_PATH_PROG(PROG_LD,ld)
AC_PROG_LD_GNU
AC_PATH_PROG(PROG_AR, ar)

AC_SUBST(STLD)
AC_SUBST(STLD_FLAGS)
AC_SUBST(BLDSHARED)
AC_SUBST(LD)
AC_SUBST(LDFLAGS)
AC_SUBST(SHLD)
AC_SUBST(SHLD_FLAGS)
AC_SUBST(SHLIBEXT)
AC_SUBST(SONAMEFLAG)
AC_SUBST(PICFLAG)

# Assume non-shared by default and override below
# these are the defaults, good for lots of systems
STLD=${PROG_AR}
STLD_FLAGS="-rcs"
BLDSHARED="false"
LD="${CC}"
LDFLAGS=""
SHLD="${CC}"
SHLD_FLAGS="-shared"
SHLIBEXT="so"
SONAMEFLAG=""
PICFLAG=""

AC_MSG_CHECKING([ability to build shared libraries])

# and these are for particular systems
case "$host_os" in
	*linux*)
		BLDSHARED="true"
		if test "${ac_cv_gnu_ld_no_default_allow_shlib_undefined}" = "yes"; then
			SHLD_FLAGS="-shared -Wl,-Bsymbolic -Wl,--allow-shlib-undefined" 
		else
			SHLD_FLAGS="-shared -Wl,-Bsymbolic" 
		fi
		LDFLAGS="-Wl,--export-dynamic"
		PICFLAGS="-fPIC"
		SONAMEFLAG="-Wl,-soname="
		;;
	*solaris*)
		BLDSHARED="true"
		SHLD_FLAGS="-G"
		SONAMEFLAG="-h "
		if test "${GCC}" = "yes"; then
			PICFLAGS="-fPIC"
			SONAMEFLAG="-Wl,-soname="
			if test "${ac_cv_prog_gnu_ld}" = "yes"; then
				LDFLAGS="-Wl,-E"
			fi
		else
			PICFLAGS="-KPIC"
			## ${CFLAGS} added for building 64-bit shared 
			## libs using Sun's Compiler
			SHLD_FLAGS="-G \${CFLAGS}"
		fi
		;;
	*sunos*)
		BLDSHARED="true"
		SHLD_FLAGS="-G"
		SONAMEFLAG="-Wl,-h,"
		PICFLAGS="-KPIC"   # Is this correct for SunOS
		;;
	*netbsd* | *freebsd* | *dragonfly* )  
		BLDSHARED="true"
		LDFLAGS="-Wl,--export-dynamic"
		SONAMEFLAG="-Wl,-soname,"
		PICFLAGS="-fPIC -DPIC"
		;;
	*openbsd*)
		BLDSHARED="true"
		LDFLAGS="-Wl,-Bdynamic"
		SONAMEFLAG="-Wl,-soname,"
		PICFLAGS="-fPIC"
		;;
	*irix*)
		BLDSHARED="true"
		SHLD_FLAGS="-set_version sgi1.0 -shared"
		SONAMEFLAG="-soname "
		SHLD="${PROG_LD}"
		if test "${GCC}" = "yes"; then
			PICFLAGS="-fPIC"
		else 
			PICFLAGS="-KPIC"
		fi
		;;
	*aix*)
		BLDSHARED="true"
		SHLD_FLAGS="-Wl,-G,-bexpall"
		LDFLAGS="-Wl,-brtl,-bexpall,-bbigtoc"
		# as AIX code is always position independent...
		PICFLAGS="-O2"
		;;
	*hpux*)
		# Use special PIC flags for the native HP-UX compiler.
		if test $ac_cv_prog_cc_Ae = yes; then
			BLDSHARED="true"
			SHLD_FLAGS="-b -Wl,-B,symbolic,-b,-z"
			SONAMEFLAG="-Wl,+h "
			PICFLAGS="+z"
		elif test "${GCC}" = "yes"; then
			BLDSHARED="true" # I hope this is correct
			PICFLAGS="-fPIC"
		fi
		if test "$host_cpu" = "ia64"; then
			SHLIBEXT="so"
			LDFLAGS="-Wl,-E,+b/usr/local/lib/hpux32:/usr/lib/hpux32"
		else
			SHLIBEXT="sl"
			LDFLAGS="-Wl,-E,+b/usr/local/lib:/usr/lib"
		fi
		;;
	*osf*)
		BLDSHARED="true"
		SONAMEFLAG="-Wl,-soname,"
		PICFLAGS="-fPIC"
		;;
	*unixware*)
		BLDSHARED="true"
		SONAMEFLAG="-Wl,-soname,"
		PICFLAGS="-KPIC"
		;;
	*darwin*)
		BLDSHARED="true"
		SHLD_FLAGS="-bundle -flat_namespace -undefined suppress"
		SHLIBEXT="dylib"
		;;
esac

AC_MSG_RESULT($BLDSHARED)

AC_MSG_CHECKING([LD])
AC_MSG_RESULT([$LD])
AC_MSG_CHECKING([LDFLAGS])
AC_MSG_RESULT([$LDFLAGS])

AC_MSG_CHECKING([STLD])
AC_MSG_RESULT([$STLD])
AC_MSG_CHECKING([STLD_FLAGS])
AC_MSG_RESULT([$STLD_FLAGS])

#######################################################
# test whether building a shared library actually works
if test $BLDSHARED = true; then

AC_MSG_CHECKING([SHLD])
AC_MSG_RESULT([$SHLD])
AC_MSG_CHECKING([SHLD_FLAGS])
AC_MSG_RESULT([$SHLD_FLAGS])

AC_MSG_CHECKING([SHLIBEXT])
AC_MSG_RESULT([$SHLIBEXT])
AC_MSG_CHECKING([SONAMEFLAG])
AC_MSG_RESULT([$SONAMEFLAG])

AC_MSG_CHECKING([PICFLAG])
AC_MSG_RESULT([$PICFLAG])

AC_CACHE_CHECK([whether building shared libraries actually works], 
               [ac_cv_shlib_works],[
   ac_cv_shlib_works=no
   # try building a trivial shared library
   ${CC} ${CFLAGS} ${PICFLAG} -c ${srcdir-.}/build/tests/shlib.c -o shlib.o &&
       ${SHLD} `eval echo ${SHLD_FLAGS} ` -o shlib.${SHLIBEXT} shlib.o &&
       ac_cv_shlib_works=yes
   rm -f shlib.${SHLIBEXT} shlib.o
])
if test $ac_cv_shlib_works = no; then
   BLDSHARED=false
fi
fi

AC_ARG_ENABLE(dso,
[  --enable-dso 		Enable building internal libraries as DSO's (experimental)],
[ if test x$enable_dso != xyes; then
 	BLDSHARED=false
  fi], 
[BLDSHARED=false])
