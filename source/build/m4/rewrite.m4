AC_SYS_LARGEFILE

case "$host_os" in
	*linux*)   AC_DEFINE(LINUX,1,[Whether the host os is linux])
		;;
	*solaris*) AC_DEFINE(SUNOS5,1,[Whether the host os is solaris])
		AC_DEFINE(BROKEN_GETGRNAM,1,[Does getgrnam work correctly])
		;;
	*sunos*) AC_DEFINE(SUNOS4,1,[Whether the host os is sunos4])
		AC_DEFINE(BROKEN_GETGRNAM,1,[Does getgrnam work correctly])
		;;
	*netbsd* | *freebsd* | *dragonfly* )  
		AC_DEFINE(BROKEN_GETGRNAM,1,[Does getgrnam work correctly])
		;;
	*openbsd*)
		AC_DEFINE(BROKEN_GETGRNAM,1,[Does getgrnam work correctly])
		;;
	*irix*) AC_DEFINE(IRIX,1,[Whether the host os is irix])
		case "$host_os" in
		*irix6*) AC_DEFINE(IRIX6,1,[Whether the host os is irix6])
		;;
		esac
		;;
	*aix*) AC_DEFINE(AIX,1,[Whether the host os is aix])
		AC_DEFINE(BROKEN_STRNLEN,1,[Does strnlen work correctly])
		AC_DEFINE(BROKEN_STRNDUP,1,[Does strndup work correctly])
		;;
	*hpux*) AC_DEFINE(HPUX,1,[Whether the host os is HPUX])
		;;
	*qnx*) AC_DEFINE(QNX,1,[Whether the host os is qnx])
		;;
	*osf*) AC_DEFINE(OSF1,1,[Whether the host os is osf1])
		AC_DEFINE(BROKEN_GETGRNAM,1,[Does getgrnam work correctly])
		;;
	*sco*) AC_DEFINE(SCO,1,[Whether the host os is sco unix])
		;;
	*unixware*) AC_DEFINE(UNIXWARE,1,[Whether the host os is unixware])
		;;
	*next2*) AC_DEFINE(NEXT2,1,[Whether the host os is NeXT v2])
		;;
	*dgux*) AC_CHECK_PROG( ROFF, groff, [groff -etpsR -Tascii -man])
		;;
	*sysv4*) AC_DEFINE(SYSV,1,[Whether this is a system V system])
		case "$host" in
			*-univel-*)
				if [ test "$GCC" != yes ]; then
					AC_DEFINE(HAVE_MEMSET,1,[Whether memset() is available])
				fi
				;;
			*mips-sni-sysv4*) AC_DEFINE(RELIANTUNIX,1,[Whether the host os is reliantunix]);;
		esac
		;;
	*sysv5*) AC_DEFINE(SYSV,1,[Whether this is a system V system])
		if [ test "$GCC" != yes ]; then
			AC_DEFINE(HAVE_MEMSET,1,[Whether memset() is available])
		fi
		;;
	*vos*)
		;;
	*darwin*)   AC_DEFINE(DARWINOS,1,[Whether the host os is Darwin/MacOSX])
		;;
esac


AC_CHECK_HEADERS(stdarg.h string.h)

AC_TYPE_SIGNAL
AC_TYPE_UID_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_PID_T
AC_STRUCT_ST_RDEV
AC_CHECK_TYPE(ino_t,unsigned)
AC_CHECK_TYPE(loff_t,off_t)
AC_CHECK_TYPE(offset_t,loff_t)
AC_CHECK_TYPES(long long)

AC_FUNC_MEMCMP

AC_CHECK_FUNCS(pipe strftime srandom random srand rand usleep setbuffer)

AC_CACHE_CHECK([for working mmap],samba_cv_HAVE_MMAP,[
AC_TRY_RUN([#include "${srcdir-.}/build/tests/shared_mmap.c"],
           samba_cv_HAVE_MMAP=yes,samba_cv_HAVE_MMAP=no,samba_cv_HAVE_MMAP=cross)])
if test x"$samba_cv_HAVE_MMAP" = x"yes"; then
    AC_DEFINE(HAVE_MMAP,1,[Whether mmap works])
fi

AC_CACHE_CHECK([for O_DIRECT flag to open(2)],samba_cv_HAVE_OPEN_O_DIRECT,[
AC_TRY_COMPILE([
#include <unistd.h>
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif],
[int fd = open("/dev/null", O_DIRECT);],
samba_cv_HAVE_OPEN_O_DIRECT=yes,samba_cv_HAVE_OPEN_O_DIRECT=no)])
if test x"$samba_cv_HAVE_OPEN_O_DIRECT" = x"yes"; then
    AC_DEFINE(HAVE_OPEN_O_DIRECT,1,[Whether the open(2) accepts O_DIRECT])
fi 
