

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
AC_SEARCH_LIBS_EXT(flistxattr, [attr], XATTR_LIBS)
AC_CHECK_FUNC_EXT(flistxattr, $XATTR_LIBS)
SMB_EXT_LIB(XATTR,[${XATTR_LIBS}],[${XATTR_CFLAGS}],[${XATTR_CPPFLAGS}],[${XATTR_LDFLAGS}])
if test x"$ac_cv_func_ext_flistxattr" = x"yes"; then
	AC_DEFINE(HAVE_XATTR_SUPPORT,1,[Whether we have xattr support])
	SMB_EXT_LIB_ENABLE(XATTR,YES)
fi

AC_CHECK_HEADERS(blkid/blkid.h)
AC_SEARCH_LIBS_EXT(blkid_get_cache, [blkid], BLKID_LIBS)
AC_CHECK_FUNC_EXT(blkid_get_cache, $BLKID_LIBS)
SMB_EXT_LIB(BLKID,[${BLKID_LIBS}],[${BLKID_CFLAGS}],[${BLKID_CPPFLAGS}],[${BLKID_LDFLAGS}])
if test x"$ac_cv_func_ext_blkid_get_cache" = x"yes"; then
	AC_DEFINE(HAVE_LIBBLKID,1,[Whether we have blkid support (e2fsprogs)])
	SMB_EXT_LIB_ENABLE(BLKID,YES)
fi
