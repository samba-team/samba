

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

dnl ############################################
dnl use flistxattr as the key function for having 
dnl sufficient xattr support for posix xattr backend
AC_CHECK_HEADERS(sys/attributes.h attr/xattr.h sys/xattr.h)
AC_SEARCH_LIBS(flistxattr, [attr])

if test x"$ac_cv_func_flistxattr" = x"yes"; then
	SMB_MODULE_DEFAULT(posix_xattr, STATIC)
	AC_DEFINE(HAVE_XATTR_SUPPORT,1,[Whether we have xattr support])
fi

SMB_MODULE_MK(posix_xattr, NTVFS, NOT, ntvfs/posix/config.mk)
SMB_MODULE_MK(ntvfs_posix, NTVFS, STATIC, ntvfs/config.mk)
