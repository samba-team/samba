SMB_MODULE_MK(ntvfs_posix, NTVFS, STATIC, ntvfs/config.mk)


dnl #############################################
dnl see if we have nanosecond resolution for stat
AC_CACHE_CHECK([for tv_nsec nanosecond fields in struct stat],ac_cv_have_stat_tv_nsec,[
AC_TRY_COMPILE(
[
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
],
[struct stat st; 
 st.st_mtim.tv_nsec;
 st.st_atim.tv_nsec;
 st.st_ctim.tv_nsec;
],
ac_cv_decl_have_stat_tv_nsec=yes,
ac_cv_decl_have_stat_tv_nsec=no)
])
if test x"$ac_cv_decl_have_stat_tv_nsec" = x"yes"; then
   AC_DEFINE(HAVE_STAT_TV_NSEC,1,[Whether stat has tv_nsec nanosecond fields])
fi


################################################
# look for a method of setting the effective uid
seteuid=no;
if test $seteuid = no; then
AC_CACHE_CHECK([for setresuid],samba_cv_USE_SETRESUID,[
AC_TRY_RUN([
#define AUTOCONF_TEST 1
#define USE_SETRESUID 1
#include "confdefs.h"
#include "${srcdir-.}/lib/util_sec.c"],
           samba_cv_USE_SETRESUID=yes,samba_cv_USE_SETRESUID=no,samba_cv_USE_SETRESUID=cross)])
if test x"$samba_cv_USE_SETRESUID" = x"yes"; then
    seteuid=yes;AC_DEFINE(USE_SETRESUID,1,[Whether setresuid() is available])
fi
fi


if test $seteuid = no; then
AC_CACHE_CHECK([for setreuid],samba_cv_USE_SETREUID,[
AC_TRY_RUN([
#define AUTOCONF_TEST 1
#define USE_SETREUID 1
#include "confdefs.h"
#include "${srcdir-.}/lib/util_sec.c"],
           samba_cv_USE_SETREUID=yes,samba_cv_USE_SETREUID=no,samba_cv_USE_SETREUID=cross)])
if test x"$samba_cv_USE_SETREUID" = x"yes"; then
    seteuid=yes;AC_DEFINE(USE_SETREUID,1,[Whether setreuid() is available])
fi
fi

if test $seteuid = no; then
AC_CACHE_CHECK([for seteuid],samba_cv_USE_SETEUID,[
AC_TRY_RUN([
#define AUTOCONF_TEST 1
#define USE_SETEUID 1
#include "confdefs.h"
#include "${srcdir-.}/lib/util_sec.c"],
           samba_cv_USE_SETEUID=yes,samba_cv_USE_SETEUID=no,samba_cv_USE_SETEUID=cross)])
if test x"$samba_cv_USE_SETEUID" = x"yes"; then
    seteuid=yes;AC_DEFINE(USE_SETEUID,1,[Whether seteuid() is available])
fi
fi

if test $seteuid = no; then
AC_CACHE_CHECK([for setuidx],samba_cv_USE_SETUIDX,[
AC_TRY_RUN([
#define AUTOCONF_TEST 1
#define USE_SETUIDX 1
#include "confdefs.h"
#include "${srcdir-.}/lib/util_sec.c"],
           samba_cv_USE_SETUIDX=yes,samba_cv_USE_SETUIDX=no,samba_cv_USE_SETUIDX=cross)])
if test x"$samba_cv_USE_SETUIDX" = x"yes"; then
    seteuid=yes;AC_DEFINE(USE_SETUIDX,1,[Whether setuidx() is available])
fi
fi
