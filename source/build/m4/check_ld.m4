dnl SMB Build Environment LD Checks
dnl -------------------------------------------------------
dnl  Copyright (C) Stefan (metze) Metzmacher 2004
dnl  Copyright (C) Jelmer Vernooij 2006
dnl  Released under the GNU GPL
dnl -------------------------------------------------------
dnl
dnl Check if we use GNU ld
AC_PATH_PROG(LD, ld)
AC_PROG_LD_GNU
AC_PATH_PROG(AR, ar)

AC_SUBST(SHLIBEXT)
AC_SUBST(LDSHFLAGS)
AC_SUBST(SONAMEFLAG)
AC_SUBST(DYNEXP)
AC_SUBST(PICFLAG)

AC_SUBST(BLDSHARED)
# Assume non-shared by default and override below
BLDSHARED="false"

# these are the defaults, good for lots of systems
DYNEXP=
HOST_OS="$host_os"
LDSHFLAGS="-shared"
SONAMEFLAG=""
SHLD="\${CC}"
PICFLAG=""
PICSUFFIX="po"
SHLIBEXT="so"

AC_MSG_CHECKING([ability to build shared libraries])

# and these are for particular systems
case "$host_os" in
	*linux*)   AC_DEFINE(LINUX,1,[Whether the host os is linux])
		BLDSHARED="true"
		LDSHFLAGS="-shared" 
		DYNEXP="-Wl,--export-dynamic"
		PICFLAG="-fPIC"
		SONAMEFLAG="-Wl,-soname="
		AC_DEFINE(STAT_ST_BLOCKSIZE,512)
		;;
	*solaris*) AC_DEFINE(SUNOS5,1,[Whether the host os is solaris])
		BLDSHARED="true"
		LDSHFLAGS="-G"
		if test "${GCC}" = "yes"; then
			PICFLAG="-fPIC"
			if test "${ac_cv_prog_gnu_ld}" = "yes"; then
				DYNEXP="-Wl,-E"
			fi
		else
			PICFLAG="-KPIC"
			## ${CFLAGS} added for building 64-bit shared 
			## libs using Sun's Compiler
			LDSHFLAGS="-G \${CFLAGS}"
			PICSUFFIX="po.o"
		fi
		AC_DEFINE(STAT_ST_BLOCKSIZE,512,[The size of a block])
		;;
	*sunos*) AC_DEFINE(SUNOS4,1,[Whether the host os is sunos4])
		BLDSHARED="true"
		LDSHFLAGS="-G"
		PICFLAG="-KPIC"   # Is this correct for SunOS
		AC_DEFINE(STAT_ST_BLOCKSIZE,512)
		;;
	*netbsd* | *freebsd*)  BLDSHARED="true"
		LDSHFLAGS="-shared"
		DYNEXP="-Wl,--export-dynamic"
		PICFLAG="-fPIC -DPIC"
		AC_DEFINE(STAT_ST_BLOCKSIZE,512,[The size of a block])
		;;
	*openbsd*)  BLDSHARED="true"
		LDSHFLAGS="-shared"
		DYNEXP="-Wl,-Bdynamic"
		PICFLAG="-fPIC"
		AC_DEFINE(STAT_ST_BLOCKSIZE,512,[The size of a block])
		;;
	*irix*) AC_DEFINE(IRIX,1,[Whether the host os is irix])
		ATTEMPT_WRAP32_BUILD=yes
		BLDSHARED="true"
		LDSHFLAGS="-set_version sgi1.0 -shared"
		SONAMEFLAG="-soname "
		SHLD="\${LD}"
		if test "${GCC}" = "yes"; then
			PICFLAG="-fPIC"
		else 
			PICFLAG="-KPIC"
		fi
		AC_DEFINE(STAT_ST_BLOCKSIZE,512,[The size of a block])
		;;
	*aix*) AC_DEFINE(AIX,1,[Whether the host os is aix])
		BLDSHARED="true"
		LDSHFLAGS="-Wl,-bexpall,-bM:SRE,-bnoentry,-berok"
		DYNEXP="-Wl,-brtl,-bexpall,-bbigtoc"
		PICFLAG="-O2"
		if test "${GCC}" != "yes"; then
			## for funky AIX compiler using strncpy()
			CFLAGS="$CFLAGS -D_LINUX_SOURCE_COMPAT -qmaxmem=32000"
		fi

		AC_DEFINE(STAT_ST_BLOCKSIZE,DEV_BSIZE,[The size of a block])
		;;
	*hpux*) AC_DEFINE(HPUX,1,[Whether the host os is HPUX])
		SHLIBEXT="sl"
		# Use special PIC flags for the native HP-UX compiler.
		if test $ac_cv_prog_cc_Ae = yes; then
			BLDSHARED="true"
			SHLD="/usr/bin/ld"
			LDSHFLAGS="-B symbolic -b -z"
			SONAMEFLAG="+h "
			PICFLAG="+z"
		fi
		DYNEXP="-Wl,-E"
		AC_DEFINE(STAT_ST_BLOCKSIZE,8192,[The size of a block])
		;;
	*qnx*) AC_DEFINE(QNX,1,[Whether the host os is qnx])
		AC_DEFINE(STAT_ST_BLOCKSIZE,512)
		;;
	*osf*) AC_DEFINE(OSF1,1,[Whether the host os is osf1])
		BLDSHARED="true"
		LDSHFLAGS="-shared"
		SONAMEFLAG="-Wl,-soname,"
		PICFLAG="-fPIC"
		AC_DEFINE(STAT_ST_BLOCKSIZE,512)
		;;
	*sco*) AC_DEFINE(SCO,1,[Whether the host os is sco unix])
		AC_DEFINE(STAT_ST_BLOCKSIZE,512)
		;;
	*unixware*) AC_DEFINE(UNIXWARE,1,[Whether the host os is unixware])
		BLDSHARED="true"
		LDSHFLAGS="-shared"
		SONAMEFLAG="-Wl,-soname,"
		PICFLAG="-KPIC"
		AC_DEFINE(STAT_ST_BLOCKSIZE,512)
		;;
	*next2*) AC_DEFINE(NEXT2,1,[Whether the host os is NeXT v2])
		AC_DEFINE(STAT_ST_BLOCKSIZE,512)
		;;
	*dgux*) AC_CHECK_PROG( ROFF, groff, [groff -etpsR -Tascii -man])
		AC_DEFINE(STAT_ST_BLOCKSIZE,512)
		;;
	*sysv4*) AC_DEFINE(SYSV,1,[Whether this is a system V system])
		case "$host" in
			*-univel-*)     if [ test "$GCC" != yes ]; then
					AC_DEFINE(HAVE_MEMSET,1,[Whether memset() is available])
				fi
				LDSHFLAGS="-G"
                            		DYNEXP="-Bexport"
			;;
			*mips-sni-sysv4*) AC_DEFINE(RELIANTUNIX,1,[Whether the host os is reliantunix]);;
		esac
		AC_DEFINE(STAT_ST_BLOCKSIZE,512)
		;;

	*sysv5*) AC_DEFINE(SYSV,1,[Whether this is a system V system])
		if [ test "$GCC" != yes ]; then
			AC_DEFINE(HAVE_MEMSET,1,[Whether memset() is available])
		fi
		LDSHFLAGS="-G"
		AC_DEFINE(STAT_ST_BLOCKSIZE,512)
		;;
	*-vms)
		BLDSHARED="false"
		LDSHFLAGS=""
		;;
	*vos*) AC_DEFINE(STAT_ST_BLOCKSIZE,4096)
		BLDSHARED="false"
		LDSHFLAGS=""
		;;
	*)
		AC_DEFINE(STAT_ST_BLOCKSIZE,512)
		;;
esac
AC_MSG_RESULT($BLDSHARED)
AC_MSG_CHECKING([linker flags for shared libraries])
AC_MSG_RESULT([$LDSHFLAGS])
AC_MSG_CHECKING([compiler flags for position-independent code])
AC_MSG_RESULT([$PICFLAGS])

#######################################################
# test whether building a shared library actually works
if test $BLDSHARED = true; then
AC_CACHE_CHECK([whether building shared libraries actually works], 
               [ac_cv_shlib_works],[
   ac_cv_shlib_works=no
   # try building a trivial shared library
   if test "$PICSUFFIX" = "po"; then
     $CC $CPPFLAGS $CFLAGS $PICFLAG -c -o shlib.po ${srcdir-.}/build/tests/shlib.c &&
       $CC $CPPFLAGS $CFLAGS `eval echo $LDSHFLAGS` -o shlib.so shlib.po &&
       ac_cv_shlib_works=yes
   else
     $CC $CPPFLAGS $CFLAGS $PICFLAG -c -o shlib.$PICSUFFIX ${srcdir-.}/build/tests/shlib.c &&
       mv shlib.$PICSUFFIX shlib.po &&
       $CC $CPPFLAGS $CFLAGS `eval echo $LDSHFLAGS` -o shlib.so shlib.po &&
       ac_cv_shlib_works=yes
   fi
   rm -f shlib.so shlib.po
])
if test $ac_cv_shlib_works = no; then
   BLDSHARED=false
fi
fi


