dnl Checks for programs.
dnl Unique-to-Samba variables we'll be playing with.

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

AC_CHECK_HEADERS(stdarg.h string.h )


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

AC_FUNC_MEMCMP

AC_CHECK_FUNCS(setsid pipe crypt16 getauthuid)
AC_CHECK_FUNCS(strftime sigprocmask sigblock sigaction)
AC_CHECK_FUNCS(setgroups sysconf getpwanam srandom random srand rand usleep)
AC_CHECK_FUNCS(backtrace setbuffer)

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


AC_CACHE_CHECK([for ftruncate extend],samba_cv_HAVE_FTRUNCATE_EXTEND,[
AC_TRY_RUN([#include "${srcdir-.}/build/tests/ftruncate.c"],
           samba_cv_HAVE_FTRUNCATE_EXTEND=yes,samba_cv_HAVE_FTRUNCATE_EXTEND=no,samba_cv_HAVE_FTRUNCATE_EXTEND=cross)])
if test x"$samba_cv_HAVE_FTRUNCATE_EXTEND" = x"yes"; then
    AC_DEFINE(HAVE_FTRUNCATE_EXTEND,1,[Truncate extend])
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
