dnl Checks for programs.
dnl Unique-to-Samba variables we'll be playing with.

DYNEXP=

AC_SUBST(SHLIBEXT)
AC_SUBST(LDSHFLAGS)
AC_SUBST(SONAMEFLAG)
AC_SUBST(PICFLAG)

AC_DEFINE([_GNU_SOURCE],[],[Pull in GNU extensions])
AC_SYS_LARGEFILE

#
# Config CPPFLAG settings for strange OS's that must be set
# before other tests.
#
case "$host_os" in
# Try to work out if this is the native HPUX compiler that uses the -Ae flag.
    *hpux*)    
      AC_PROG_CC_FLAG(Ae)
      # mmap on HPUX is completely broken...
      AC_DEFINE(MMAP_BLACKLIST, 1, [Whether MMAP is broken])
      if test $ac_cv_prog_cc_Ae = yes; then
        CPPFLAGS="$CPPFLAGS -Ae"
      fi
    ;;
#
# VOS may need to have POSIX support and System V compatibility enabled.
#
    *vos*)
          case "$CPPFLAGS" in
	      *-D_POSIX_C_SOURCE*)
		;;
	  *)
		CPPFLAGS="$CPPFLAGS -D_POSIX_C_SOURCE=200112L"
		AC_DEFINE(_POSIX_C_SOURCE, 200112L, [Whether to enable POSIX support])
		;;
          esac
          case "$CPPFLAGS" in
	     *-D_SYSV*|*-D_SVID_SOURCE*)
		;;
	     *)
		CPPFLAGS="$CPPFLAGS -D_SYSV"
		AC_DEFINE(_SYSV, 1, [Whether to enable System V compatibility])
          esac
    ;;

esac


AC_HEADER_DIRENT
AC_HEADER_TIME
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS(sys/select.h fcntl.h sys/fcntl.h sys/time.h)
AC_CHECK_HEADERS(utime.h grp.h sys/id.h limits.h memory.h compat.h math.h)
AC_CHECK_HEADERS(sys/param.h ctype.h sys/wait.h sys/resource.h sys/ioctl.h sys/ipc.h sys/mode.h)
AC_CHECK_HEADERS(sys/mman.h sys/filio.h sys/priv.h sys/shm.h string.h strings.h stdlib.h)
AC_CHECK_HEADERS(sys/vfs.h sys/fs/s5param.h sys/filsys.h termios.h termio.h)
AC_CHECK_HEADERS(fnmatch.h pwd.h sys/termio.h sys/time.h sys/statfs.h sys/statvfs.h stdarg.h)
AC_CHECK_HEADERS(stdint.h inttypes.h locale.h shadow.h)
AC_CHECK_HEADERS(nss.h nss_common.h ns_api.h sys/security.h security/pam_appl.h)
AC_CHECK_HEADERS(sys/capability.h sys/acl.h)

AC_CHECK_HEADERS(sys/mount.h, , , [AC_INCLUDES_DEFAULT
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif])


AC_TYPE_SIGNAL
AC_TYPE_UID_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_PID_T
AC_STRUCT_ST_RDEV
AC_DIRENT_D_OFF
AC_CHECK_TYPE(ino_t,unsigned)
AC_CHECK_TYPE(loff_t,off_t)
AC_CHECK_TYPE(offset_t,loff_t)
AC_CHECK_TYPES(long long)


AC_CACHE_CHECK([for sig_atomic_t type],samba_cv_sig_atomic_t, [
    AC_TRY_COMPILE([
#include <sys/types.h>
#if STDC_HEADERS
#include <stdlib.h>
#include <stddef.h>
#endif
#include <signal.h>],[sig_atomic_t i = 0],
	samba_cv_sig_atomic_t=yes,samba_cv_sig_atomic_t=no)])
if test x"$samba_cv_sig_atomic_t" = x"yes"; then
   AC_DEFINE(HAVE_SIG_ATOMIC_T_TYPE,1,[Whether we have the atomic_t variable type])
fi

AC_FUNC_MEMCMP

AC_CHECK_FUNCS(setsid pipe crypt16 getauthuid)
AC_CHECK_FUNCS(strftime sigprocmask sigblock sigaction)
AC_CHECK_FUNCS(setgroups sysconf getpwanam srandom random srand rand usleep)
AC_CHECK_FUNCS(backtrace setbuffer)

AC_SUBST(BLDSHARED)
AC_SUBST(BLDMERGED)
# Assume non-shared by default and override below
BLDSHARED="false"
BLDMERGED="true"

# these are the defaults, good for lots of systems
HOST_OS="$host_os"
LDSHFLAGS="-shared"
SONAMEFLAG="#"
SHLD="\${CC}"
PICFLAG=""
PICSUFFIX="po"
POBAD_CC="#"
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
		SONAMEFLAG="-h "
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
			POBAD_CC=""
			PICSUFFIX="po.o"
		fi
		AC_DEFINE(STAT_ST_BLOCKSIZE,512,[The size of a block])
		;;
	*sunos*) AC_DEFINE(SUNOS4,1,[Whether the host os is sunos4])
		BLDSHARED="true"
		LDSHFLAGS="-G"
		SONAMEFLAG="-Wl,-h,"
		PICFLAG="-KPIC"   # Is this correct for SunOS
		AC_DEFINE(STAT_ST_BLOCKSIZE,512)
		;;
	*netbsd* | *freebsd*)  BLDSHARED="true"
		LDSHFLAGS="-shared"
		DYNEXP="-Wl,--export-dynamic"
		SONAMEFLAG="-Wl,-soname,"
		PICFLAG="-fPIC -DPIC"
		AC_DEFINE(STAT_ST_BLOCKSIZE,512,[The size of a block])
		;;
	*openbsd*)  BLDSHARED="true"
		LDSHFLAGS="-shared"
		DYNEXP="-Wl,-Bdynamic"
		SONAMEFLAG="-Wl,-soname,"
		PICFLAG="-fPIC"
		AC_DEFINE(STAT_ST_BLOCKSIZE,512,[The size of a block])
		;;
	*irix*) AC_DEFINE(IRIX,1,[Whether the host os is irix])
		case "$host_os" in
		*irix6*) AC_DEFINE(IRIX6,1,[Whether the host os is irix6])
		;;
		esac
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
		LDSHFLAGS="-Wl,-bexpall,-bM:SRE,-bnoentry"
		DYNEXP="-Wl,-brtl,-bexpall"
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
		BLDMERGED="false"
		BLDSHARED="false"
		LDSHFLAGS=""
		;;
	*vos*) AC_DEFINE(STAT_ST_BLOCKSIZE,4096)
		BLDSHARED="false"
		BLDMERGED="false"
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

AC_CACHE_CHECK([for __FUNCTION__ macro],samba_cv_HAVE_FUNCTION_MACRO,[
AC_TRY_COMPILE([#include <stdio.h>], [printf("%s\n", __FUNCTION__);],
samba_cv_HAVE_FUNCTION_MACRO=yes,samba_cv_HAVE_FUNCTION_MACRO=no)])
if test x"$samba_cv_HAVE_FUNCTION_MACRO" = x"yes"; then
    AC_DEFINE(HAVE_FUNCTION_MACRO,1,[Whether there is a __FUNCTION__ macro])
fi

AC_CACHE_CHECK([if gettimeofday takes tz argument],samba_cv_HAVE_GETTIMEOFDAY_TZ,[
AC_TRY_RUN([
#include <sys/time.h>
#include <unistd.h>
main() { struct timeval tv; exit(gettimeofday(&tv, NULL));}],
           samba_cv_HAVE_GETTIMEOFDAY_TZ=yes,samba_cv_HAVE_GETTIMEOFDAY_TZ=no,samba_cv_HAVE_GETTIMEOFDAY_TZ=cross)])
if test x"$samba_cv_HAVE_GETTIMEOFDAY_TZ" = x"yes"; then
    AC_DEFINE(HAVE_GETTIMEOFDAY_TZ,1,[Whether gettimeofday() is available])
fi

AC_CACHE_CHECK([for va_copy],samba_cv_HAVE_VA_COPY,[
AC_TRY_LINK([#include <stdarg.h>
va_list ap1,ap2;], [va_copy(ap1,ap2);],
samba_cv_HAVE_VA_COPY=yes,samba_cv_HAVE_VA_COPY=no)])
if test x"$samba_cv_HAVE_VA_COPY" = x"yes"; then
    AC_DEFINE(HAVE_VA_COPY,1,[Whether va_copy() is available])
fi

if test x"$samba_cv_HAVE_VA_COPY" != x"yes"; then
AC_CACHE_CHECK([for __va_copy],samba_cv_HAVE___VA_COPY,[
AC_TRY_LINK([#include <stdarg.h>
va_list ap1,ap2;], [__va_copy(ap1,ap2);],
samba_cv_HAVE___VA_COPY=yes,samba_cv_HAVE___VA_COPY=no)])
if test x"$samba_cv_HAVE___VA_COPY" = x"yes"; then
    AC_DEFINE(HAVE___VA_COPY,1,[Whether __va_copy() is available])
fi
fi


AC_CACHE_CHECK([for utimbuf],samba_cv_HAVE_UTIMBUF,[
AC_TRY_COMPILE([#include <sys/types.h>
#include <utime.h>],
[struct utimbuf tbuf;  tbuf.actime = 0; tbuf.modtime = 1; exit(utime("foo.c",&tbuf));],
samba_cv_HAVE_UTIMBUF=yes,samba_cv_HAVE_UTIMBUF=no,samba_cv_HAVE_UTIMBUF=cross)])
if test x"$samba_cv_HAVE_UTIMBUF" = x"yes"; then
    AC_DEFINE(HAVE_UTIMBUF,1,[Whether struct utimbuf is available])
fi

AC_CACHE_CHECK([for Linux kernel oplocks],samba_cv_HAVE_KERNEL_OPLOCKS_LINUX,[
AC_TRY_RUN([
#include <sys/types.h>
#include <fcntl.h>
#ifndef F_GETLEASE
#define F_GETLEASE	1025
#endif
main() {
       int fd = open("/dev/null", O_RDONLY);
       return fcntl(fd, F_GETLEASE, 0) == -1;
}
],
samba_cv_HAVE_KERNEL_OPLOCKS_LINUX=yes,samba_cv_HAVE_KERNEL_OPLOCKS_LINUX=no,samba_cv_HAVE_KERNEL_OPLOCKS_LINUX=cross)])
if test x"$samba_cv_HAVE_KERNEL_OPLOCKS_LINUX" = x"yes"; then
    AC_DEFINE(HAVE_KERNEL_OPLOCKS_LINUX,1,[Whether to use linux kernel oplocks])
fi

AC_CACHE_CHECK([for kernel change notify support],samba_cv_HAVE_KERNEL_CHANGE_NOTIFY,[
AC_TRY_RUN([
#include <sys/types.h>
#include <fcntl.h>
#include <signal.h>
#ifndef F_NOTIFY
#define F_NOTIFY 1026
#endif
main() {
       	exit(fcntl(open("/tmp", O_RDONLY), F_NOTIFY, 0) == -1 ?  1 : 0);
}
],
samba_cv_HAVE_KERNEL_CHANGE_NOTIFY=yes,samba_cv_HAVE_KERNEL_CHANGE_NOTIFY=no,samba_cv_HAVE_KERNEL_CHANGE_NOTIFY=cross)])
if test x"$samba_cv_HAVE_KERNEL_CHANGE_NOTIFY" = x"yes"; then
    AC_DEFINE(HAVE_KERNEL_CHANGE_NOTIFY,1,[Whether kernel notifies changes])
fi

AC_CACHE_CHECK([for kernel share modes],samba_cv_HAVE_KERNEL_SHARE_MODES,[
AC_TRY_RUN([
#include <sys/types.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/file.h>
#ifndef LOCK_MAND
#define LOCK_MAND	32
#define LOCK_READ	64
#endif
main() {
       	exit(flock(open("/dev/null", O_RDWR), LOCK_MAND|LOCK_READ) != 0);
}
],
samba_cv_HAVE_KERNEL_SHARE_MODES=yes,samba_cv_HAVE_KERNEL_SHARE_MODES=no,samba_cv_HAVE_KERNEL_SHARE_MODES=cross)])
if test x"$samba_cv_HAVE_KERNEL_SHARE_MODES" = x"yes"; then
    AC_DEFINE(HAVE_KERNEL_SHARE_MODES,1,[Whether the kernel supports share modes])
fi

AC_CACHE_CHECK([for IRIX kernel oplock type definitions],samba_cv_HAVE_KERNEL_OPLOCKS_IRIX,[
AC_TRY_COMPILE([#include <sys/types.h>
#include <fcntl.h>],
[oplock_stat_t t; t.os_state = OP_REVOKE; t.os_dev = 1; t.os_ino = 1;],
samba_cv_HAVE_KERNEL_OPLOCKS_IRIX=yes,samba_cv_HAVE_KERNEL_OPLOCKS_IRIX=no)])
if test x"$samba_cv_HAVE_KERNEL_OPLOCKS_IRIX" = x"yes"; then
    AC_DEFINE(HAVE_KERNEL_OPLOCKS_IRIX,1,[Whether IRIX kernel oplock type definitions are available])
fi

AC_CACHE_CHECK([for irix specific capabilities],samba_cv_HAVE_IRIX_SPECIFIC_CAPABILITIES,[
AC_TRY_RUN([#include <sys/types.h>
#include <sys/capability.h>
main() {
 cap_t cap;
 if ((cap = cap_get_proc()) == NULL)
   exit(1);
 cap->cap_effective |= CAP_NETWORK_MGT;
 cap->cap_inheritable |= CAP_NETWORK_MGT;
 cap_set_proc(cap);
 exit(0);
}
],
samba_cv_HAVE_IRIX_SPECIFIC_CAPABILITIES=yes,samba_cv_HAVE_IRIX_SPECIFIC_CAPABILITIES=no,samba_cv_HAVE_IRIX_SPECIFIC_CAPABILITIES=cross)])
if test x"$samba_cv_HAVE_IRIX_SPECIFIC_CAPABILITIES" = x"yes"; then
    AC_DEFINE(HAVE_IRIX_SPECIFIC_CAPABILITIES,1,[Whether IRIX specific capabilities are available])
fi


AC_CACHE_CHECK([for ftruncate extend],samba_cv_HAVE_FTRUNCATE_EXTEND,[
AC_TRY_RUN([#include "${srcdir-.}/build/tests/ftruncate.c"],
           samba_cv_HAVE_FTRUNCATE_EXTEND=yes,samba_cv_HAVE_FTRUNCATE_EXTEND=no,samba_cv_HAVE_FTRUNCATE_EXTEND=cross)])
if test x"$samba_cv_HAVE_FTRUNCATE_EXTEND" = x"yes"; then
    AC_DEFINE(HAVE_FTRUNCATE_EXTEND,1,[Truncate extend])
fi

AC_CACHE_CHECK([for broken getgroups],samba_cv_HAVE_BROKEN_GETGROUPS,[
AC_TRY_RUN([#include "${srcdir-.}/build/tests/getgroups.c"],
           samba_cv_HAVE_BROKEN_GETGROUPS=yes,samba_cv_HAVE_BROKEN_GETGROUPS=no,samba_cv_HAVE_BROKEN_GETGROUPS=cross)])
if test x"$samba_cv_HAVE_BROKEN_GETGROUPS" = x"yes"; then
    AC_DEFINE(HAVE_BROKEN_GETGROUPS,1,[Whether getgroups is broken])
fi

AC_CACHE_CHECK([for sysconf(_SC_NGROUPS_MAX)],samba_cv_SYSCONF_SC_NGROUPS_MAX,[
AC_TRY_RUN([#include <unistd.h>
main() { exit(sysconf(_SC_NGROUPS_MAX) == -1 ? 1 : 0); }],
samba_cv_SYSCONF_SC_NGROUPS_MAX=yes,samba_cv_SYSCONF_SC_NGROUPS_MAX=no,samba_cv_SYSCONF_SC_NGROUPS_MAX=cross)])
if test x"$samba_cv_SYSCONF_SC_NGROUPS_MAX" = x"yes"; then
    AC_DEFINE(SYSCONF_SC_NGROUPS_MAX,1,[Whether sysconf(_SC_NGROUPS_MAX) is available])
fi

AC_CACHE_CHECK([for working mmap],samba_cv_HAVE_MMAP,[
AC_TRY_RUN([#include "${srcdir-.}/build/tests/shared_mmap.c"],
           samba_cv_HAVE_MMAP=yes,samba_cv_HAVE_MMAP=no,samba_cv_HAVE_MMAP=cross)])
if test x"$samba_cv_HAVE_MMAP" = x"yes"; then
    AC_DEFINE(HAVE_MMAP,1,[Whether mmap works])
fi

AC_CACHE_CHECK([for st_blocks in struct stat],samba_cv_HAVE_STAT_ST_BLOCKS,[
AC_TRY_COMPILE([#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>],
[struct stat st;  st.st_blocks = 0;],
samba_cv_HAVE_STAT_ST_BLOCKS=yes,samba_cv_HAVE_STAT_ST_BLOCKS=no,samba_cv_HAVE_STAT_ST_BLOCKS=cross)])
if test x"$samba_cv_HAVE_STAT_ST_BLOCKS" = x"yes"; then
    AC_DEFINE(HAVE_STAT_ST_BLOCKS,1,[Whether the stat struct has a st_block property])
fi 

AC_CACHE_CHECK([for st_blksize in struct stat],samba_cv_HAVE_STAT_ST_BLKSIZE,[
AC_TRY_COMPILE([#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>],
[struct stat st;  st.st_blksize = 0;],
samba_cv_HAVE_STAT_ST_BLKSIZE=yes,samba_cv_HAVE_STAT_ST_BLKSIZE=no,samba_cv_HAVE_STAT_ST_BLKSIZE=cross)])
if test x"$samba_cv_HAVE_STAT_ST_BLKSIZE" = x"yes"; then
    AC_DEFINE(HAVE_STAT_ST_BLKSIZE,1,[Whether the stat struct has a st_blksize property])
fi

case "$host_os" in
*linux*)
AC_CACHE_CHECK([for broken RedHat 7.2 system header files],samba_cv_BROKEN_REDHAT_7_SYSTEM_HEADERS,[
AC_TRY_COMPILE([
#ifdef HAVE_SYS_VFS_H
#include <sys/vfs.h>
#endif
#ifdef HAVE_SYS_CAPABILITY_H
#include <sys/capability.h>
#endif
],[int i;],
   samba_cv_BROKEN_REDHAT_7_SYSTEM_HEADERS=no,samba_cv_BROKEN_REDHAT_7_SYSTEM_HEADERS=yes)])
if test x"$samba_cv_BROKEN_REDHAT_7_SYSTEM_HEADERS" = x"yes"; then
   AC_DEFINE(BROKEN_REDHAT_7_SYSTEM_HEADERS,1,[Broken RedHat 7.2 system header files])
fi
;;
esac

###############################################
# test for where we get crypt() from
AC_CHECK_LIB_EXT(crypt, CRYPT_LIBS, crypt)
SMB_EXT_LIB_ENABLE(CRYPT,YES)
SMB_EXT_LIB(CRYPT, $CRYPT_LIBS)

##
## moved after the check for -lcrypt in order to
## ensure that the necessary libraries are included
## check checking for truncated salt.  Wrapped by the
## $with_pam_for_crypt variable as above   --jerry
##
if test x"$with_pam_for_crypt" != x"yes"; then
AC_CACHE_CHECK([for a crypt that needs truncated salt],samba_cv_HAVE_TRUNCATED_SALT,[
crypt_LIBS="$LIBS"
LIBS="$AUTHLIBS $LIBS"
AC_TRY_RUN([#include "${srcdir-.}/build/tests/crypttest.c"],
	samba_cv_HAVE_TRUNCATED_SALT=no,samba_cv_HAVE_TRUNCATED_SALT=yes,samba_cv_HAVE_TRUNCATED_SALT=cross)
LIBS="$crypt_LIBS"])
if test x"$samba_cv_HAVE_TRUNCATED_SALT" = x"yes"; then
	AC_DEFINE(HAVE_TRUNCATED_SALT,1,[Whether crypt needs truncated salt])
fi
fi

#################################################
# these tests are taken from the GNU fileutils package
AC_CHECKING(how to get filesystem space usage)
space=no

# Test for statvfs64.
if test $space = no; then
  # SVR4
  AC_CACHE_CHECK([statvfs64 function (SVR4)], fu_cv_sys_stat_statvfs64,
  [AC_TRY_RUN([
#if defined(HAVE_UNISTD_H)
#include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/statvfs.h>
  main ()
  {
    struct statvfs64 fsd;
    exit (statvfs64 (".", &fsd));
  }],
  fu_cv_sys_stat_statvfs64=yes,
  fu_cv_sys_stat_statvfs64=no,
  fu_cv_sys_stat_statvfs64=cross)])
  if test $fu_cv_sys_stat_statvfs64 = yes; then
    space=yes
    AC_DEFINE(STAT_STATVFS64,1,[Whether statvfs64() is available])
  fi
fi

# Perform only the link test since it seems there are no variants of the
# statvfs function.  This check is more than just AC_CHECK_FUNCS(statvfs)
# because that got a false positive on SCO OSR5.  Adding the declaration
# of a `struct statvfs' causes this test to fail (as it should) on such
# systems.  That system is reported to work fine with STAT_STATFS4 which
# is what it gets when this test fails.
if test $space = no; then
  # SVR4
  AC_CACHE_CHECK([statvfs function (SVR4)], fu_cv_sys_stat_statvfs,
		 [AC_TRY_LINK([#include <sys/types.h>
#include <sys/statvfs.h>],
			      [struct statvfs fsd; statvfs (0, &fsd);],
			      fu_cv_sys_stat_statvfs=yes,
			      fu_cv_sys_stat_statvfs=no)])
  if test $fu_cv_sys_stat_statvfs = yes; then
    space=yes
    AC_DEFINE(STAT_STATVFS,1,[Whether statvfs() is available])
  fi
fi

if test $space = no; then
  # DEC Alpha running OSF/1
  AC_MSG_CHECKING([for 3-argument statfs function (DEC OSF/1)])
  AC_CACHE_VAL(fu_cv_sys_stat_statfs3_osf1,
  [AC_TRY_RUN([
#include <sys/param.h>
#include <sys/types.h>
#include <sys/mount.h>
  main ()
  {
    struct statfs fsd;
    fsd.f_fsize = 0;
    exit (statfs (".", &fsd, sizeof (struct statfs)));
  }],
  fu_cv_sys_stat_statfs3_osf1=yes,
  fu_cv_sys_stat_statfs3_osf1=no,
  fu_cv_sys_stat_statfs3_osf1=no)])
  AC_MSG_RESULT($fu_cv_sys_stat_statfs3_osf1)
  if test $fu_cv_sys_stat_statfs3_osf1 = yes; then
    space=yes
    AC_DEFINE(STAT_STATFS3_OSF1,1,[Whether statfs requires 3 arguments])
  fi
fi

if test $space = no; then
# AIX
  AC_MSG_CHECKING([for two-argument statfs with statfs.bsize dnl
member (AIX, 4.3BSD)])
  AC_CACHE_VAL(fu_cv_sys_stat_statfs2_bsize,
  [AC_TRY_RUN([
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_SYS_MOUNT_H
#include <sys/mount.h>
#endif
#ifdef HAVE_SYS_VFS_H
#include <sys/vfs.h>
#endif
  main ()
  {
  struct statfs fsd;
  fsd.f_bsize = 0;
  exit (statfs (".", &fsd));
  }],
  fu_cv_sys_stat_statfs2_bsize=yes,
  fu_cv_sys_stat_statfs2_bsize=no,
  fu_cv_sys_stat_statfs2_bsize=no)])
  AC_MSG_RESULT($fu_cv_sys_stat_statfs2_bsize)
  if test $fu_cv_sys_stat_statfs2_bsize = yes; then
    space=yes
    AC_DEFINE(STAT_STATFS2_BSIZE,1,[Whether statfs requires two arguments and struct statfs has bsize property])
  fi
fi

if test $space = no; then
# SVR3
  AC_MSG_CHECKING([for four-argument statfs (AIX-3.2.5, SVR3)])
  AC_CACHE_VAL(fu_cv_sys_stat_statfs4,
  [AC_TRY_RUN([#include <sys/types.h>
#include <sys/statfs.h>
  main ()
  {
  struct statfs fsd;
  exit (statfs (".", &fsd, sizeof fsd, 0));
  }],
    fu_cv_sys_stat_statfs4=yes,
    fu_cv_sys_stat_statfs4=no,
    fu_cv_sys_stat_statfs4=no)])
  AC_MSG_RESULT($fu_cv_sys_stat_statfs4)
  if test $fu_cv_sys_stat_statfs4 = yes; then
    space=yes
    AC_DEFINE(STAT_STATFS4,1,[Whether statfs requires 4 arguments])
  fi
fi

if test $space = no; then
# 4.4BSD and NetBSD
  AC_MSG_CHECKING([for two-argument statfs with statfs.fsize dnl
member (4.4BSD and NetBSD)])
  AC_CACHE_VAL(fu_cv_sys_stat_statfs2_fsize,
  [AC_TRY_RUN([#include <sys/types.h>
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_SYS_MOUNT_H
#include <sys/mount.h>
#endif
  main ()
  {
  struct statfs fsd;
  fsd.f_fsize = 0;
  exit (statfs (".", &fsd));
  }],
  fu_cv_sys_stat_statfs2_fsize=yes,
  fu_cv_sys_stat_statfs2_fsize=no,
  fu_cv_sys_stat_statfs2_fsize=no)])
  AC_MSG_RESULT($fu_cv_sys_stat_statfs2_fsize)
  if test $fu_cv_sys_stat_statfs2_fsize = yes; then
    space=yes
	AC_DEFINE(STAT_STATFS2_FSIZE,1,[Whether statfs requires 2 arguments and struct statfs has fsize])
  fi
fi

if test $space = no; then
  # Ultrix
  AC_MSG_CHECKING([for two-argument statfs with struct fs_data (Ultrix)])
  AC_CACHE_VAL(fu_cv_sys_stat_fs_data,
  [AC_TRY_RUN([#include <sys/types.h>
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_SYS_MOUNT_H
#include <sys/mount.h>
#endif
#ifdef HAVE_SYS_FS_TYPES_H
#include <sys/fs_types.h>
#endif
  main ()
  {
  struct fs_data fsd;
  /* Ultrix's statfs returns 1 for success,
     0 for not mounted, -1 for failure.  */
  exit (statfs (".", &fsd) != 1);
  }],
  fu_cv_sys_stat_fs_data=yes,
  fu_cv_sys_stat_fs_data=no,
  fu_cv_sys_stat_fs_data=no)])
  AC_MSG_RESULT($fu_cv_sys_stat_fs_data)
  if test $fu_cv_sys_stat_fs_data = yes; then
    space=yes
    AC_DEFINE(STAT_STATFS2_FS_DATA,1,[Whether statfs requires 2 arguments and struct fs_data is available])
  fi
fi



#######################################
# Check for comparison_fn_t
AC_CACHE_CHECK([for comparison_fn_t],samba_cv_HAVE_COMPARISON_FN_T,[
AC_TRY_COMPILE([
#include <stdlib.h>
int list_find(const void *needle, 
	      const void *base, size_t nmemb, size_t size, comparison_fn_t comp_fn)
{
	return 1;
}
],[],
samba_cv_HAVE_COMPARISON_FN_T=yes,samba_cv_HAVE_COMPARISON_FN_T=no)
])
if test x"$samba_cv_HAVE_COMPARISON_FN_T" = x"yes"; then
	AC_DEFINE(HAVE_COMPARISON_FN_T,1,[Whether or not we have comparison_fn_t])
fi

