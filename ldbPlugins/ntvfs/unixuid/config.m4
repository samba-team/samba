SMB_MODULE_MK(ntvfs_unixuid, NTVFS, STATIC, ntvfs/config.mk)


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
