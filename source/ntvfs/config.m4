dnl # NTVFS Server subsystem

#################################################
# check for sendfile support

with_sendfile_support=yes
AC_MSG_CHECKING(whether to check to support sendfile)
AC_ARG_WITH(sendfile-support,
[  --with-sendfile-support Check for sendfile support (default=yes)],
[ case "$withval" in
  yes)

	AC_MSG_RESULT(yes);

	case "$host_os" in
	*linux*)
		AC_CACHE_CHECK([for linux sendfile64 support],samba_cv_HAVE_SENDFILE64,[
		AC_TRY_LINK([#include <sys/sendfile.h>],
[\
int tofd, fromfd;
off64_t offset;
size_t total;
ssize_t nwritten = sendfile64(tofd, fromfd, &offset, total);
],
samba_cv_HAVE_SENDFILE64=yes,samba_cv_HAVE_SENDFILE64=no)])

		AC_CACHE_CHECK([for linux sendfile support],samba_cv_HAVE_SENDFILE,[
		AC_TRY_LINK([#include <sys/sendfile.h>],
[\
int tofd, fromfd;
off_t offset;
size_t total;
ssize_t nwritten = sendfile(tofd, fromfd, &offset, total);
],
samba_cv_HAVE_SENDFILE=yes,samba_cv_HAVE_SENDFILE=no)])

# Try and cope with broken Linux sendfile....
		AC_CACHE_CHECK([for broken linux sendfile support],samba_cv_HAVE_BROKEN_LINUX_SENDFILE,[
		AC_TRY_LINK([\
#if defined(_FILE_OFFSET_BITS) && (_FILE_OFFSET_BITS == 64)
#undef _FILE_OFFSET_BITS
#endif
#include <sys/sendfile.h>],
[\
int tofd, fromfd;
off_t offset;
size_t total;
ssize_t nwritten = sendfile(tofd, fromfd, &offset, total);
],
samba_cv_HAVE_BROKEN_LINUX_SENDFILE=yes,samba_cv_HAVE_BROKEN_LINUX_SENDFILE=no)])

	if test x"$samba_cv_HAVE_SENDFILE64" = x"yes"; then
    		AC_DEFINE(HAVE_SENDFILE64,1,[Whether 64-bit sendfile() is available])
		AC_DEFINE(LINUX_SENDFILE_API,1,[Whether linux sendfile() API is available])
		AC_DEFINE(WITH_SENDFILE,1,[Whether sendfile() should be used])
	elif test x"$samba_cv_HAVE_SENDFILE" = x"yes"; then
    		AC_DEFINE(HAVE_SENDFILE,1,[Whether sendfile() is available])
		AC_DEFINE(LINUX_SENDFILE_API,1,[Whether linux sendfile() API is available])
		AC_DEFINE(WITH_SENDFILE,1,[Whether sendfile() should be used])
	elif test x"$samba_cv_HAVE_BROKEN_LINUX_SENDFILE" = x"yes"; then
		AC_DEFINE(LINUX_BROKEN_SENDFILE_API,1,[Whether (linux) sendfile() is broken])
		AC_DEFINE(WITH_SENDFILE,1,[Whether sendfile should be used])
	else
		AC_MSG_RESULT(no);
	fi

	;;
	*freebsd*)
		AC_CACHE_CHECK([for freebsd sendfile support],samba_cv_HAVE_SENDFILE,[
		AC_TRY_LINK([\
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/uio.h>],
[\
	int fromfd, tofd, ret, total=0;
	off_t offset, nwritten;
	struct sf_hdtr hdr;
	struct iovec hdtrl;
	hdr.headers = &hdtrl;
	hdr.hdr_cnt = 1;
	hdr.trailers = NULL;
	hdr.trl_cnt = 0;
	hdtrl.iov_base = NULL;
	hdtrl.iov_len = 0;
	ret = sendfile(fromfd, tofd, offset, total, &hdr, &nwritten, 0);
],
samba_cv_HAVE_SENDFILE=yes,samba_cv_HAVE_SENDFILE=no)])

	if test x"$samba_cv_HAVE_SENDFILE" = x"yes"; then
    		AC_DEFINE(HAVE_SENDFILE,1,[Whether sendfile() support is available])
		AC_DEFINE(FREEBSD_SENDFILE_API,1,[Whether the FreeBSD sendfile() API is available])
		AC_DEFINE(WITH_SENDFILE,1,[Whether sendfile() support should be included])
	else
		AC_MSG_RESULT(no);
	fi
	;;

	*hpux*)
		AC_CACHE_CHECK([for hpux sendfile64 support],samba_cv_HAVE_SENDFILE64,[
		AC_TRY_LINK([\
#include <sys/socket.h>
#include <sys/uio.h>],
[\
	int fromfd, tofd;
	size_t total=0;
	struct iovec hdtrl[2];
	ssize_t nwritten;
	off64_t offset;

	hdtrl[0].iov_base = 0;
	hdtrl[0].iov_len = 0;

	nwritten = sendfile64(tofd, fromfd, offset, total, &hdtrl[0], 0);
],
samba_cv_HAVE_SENDFILE64=yes,samba_cv_HAVE_SENDFILE64=no)])
	if test x"$samba_cv_HAVE_SENDFILE64" = x"yes"; then
    		AC_DEFINE(HAVE_SENDFILE64,1,[Whether sendfile64() is available])
		AC_DEFINE(HPUX_SENDFILE_API,1,[Whether the hpux sendfile() API is available])
		AC_DEFINE(WITH_SENDFILE,1,[Whether sendfile() support should be included])
	else
		AC_MSG_RESULT(no);
	fi

		AC_CACHE_CHECK([for hpux sendfile support],samba_cv_HAVE_SENDFILE,[
		AC_TRY_LINK([\
#include <sys/socket.h>
#include <sys/uio.h>],
[\
	int fromfd, tofd;
	size_t total=0;
	struct iovec hdtrl[2];
	ssize_t nwritten;
	off_t offset;

	hdtrl[0].iov_base = 0;
	hdtrl[0].iov_len = 0;

	nwritten = sendfile(tofd, fromfd, offset, total, &hdtrl[0], 0);
],
samba_cv_HAVE_SENDFILE=yes,samba_cv_HAVE_SENDFILE=no)])
	if test x"$samba_cv_HAVE_SENDFILE" = x"yes"; then
    		AC_DEFINE(HAVE_SENDFILE,1,[Whether sendfile() is available])
		AC_DEFINE(HPUX_SENDFILE_API,1,[Whether the hpux sendfile() API is available])
		AC_DEFINE(WITH_SENDFILE,1,[Whether sendfile() support should be included])
	else
		AC_MSG_RESULT(no);
	fi
	;;

	*solaris*)
		AC_CHECK_LIB(sendfile,sendfilev)
		AC_CACHE_CHECK([for solaris sendfilev64 support],samba_cv_HAVE_SENDFILEV64,[
		AC_TRY_LINK([\
#include <sys/sendfile.h>],
[\
        int sfvcnt;
        size_t xferred;
        struct sendfilevec vec[2];
	ssize_t nwritten;
	int tofd;

	sfvcnt = 2;

	vec[0].sfv_fd = SFV_FD_SELF;
	vec[0].sfv_flag = 0;
	vec[0].sfv_off = 0;
	vec[0].sfv_len = 0;

	vec[1].sfv_fd = 0;
	vec[1].sfv_flag = 0;
	vec[1].sfv_off = 0;
	vec[1].sfv_len = 0;
	nwritten = sendfilev64(tofd, vec, sfvcnt, &xferred);
],
samba_cv_HAVE_SENDFILEV64=yes,samba_cv_HAVE_SENDFILEV64=no)])

	if test x"$samba_cv_HAVE_SENDFILEV64" = x"yes"; then
    		AC_DEFINE(HAVE_SENDFILEV64,1,[Whether sendfilev64() is available])
		AC_DEFINE(SOLARIS_SENDFILE_API,1,[Whether the soloris sendfile() API is available])
		AC_DEFINE(WITH_SENDFILE,1,[Whether sendfile() support should be included])
	else
		AC_MSG_RESULT(no);
	fi

		AC_CACHE_CHECK([for solaris sendfilev support],samba_cv_HAVE_SENDFILEV,[
		AC_TRY_LINK([\
#include <sys/sendfile.h>],
[\
        int sfvcnt;
        size_t xferred;
        struct sendfilevec vec[2];
	ssize_t nwritten;
	int tofd;

	sfvcnt = 2;

	vec[0].sfv_fd = SFV_FD_SELF;
	vec[0].sfv_flag = 0;
	vec[0].sfv_off = 0;
	vec[0].sfv_len = 0;

	vec[1].sfv_fd = 0;
	vec[1].sfv_flag = 0;
	vec[1].sfv_off = 0;
	vec[1].sfv_len = 0;
	nwritten = sendfilev(tofd, vec, sfvcnt, &xferred);
],
samba_cv_HAVE_SENDFILEV=yes,samba_cv_HAVE_SENDFILEV=no)])

	if test x"$samba_cv_HAVE_SENDFILEV" = x"yes"; then
    		AC_DEFINE(HAVE_SENDFILEV,1,[Whether sendfilev() is available])
		AC_DEFINE(SOLARIS_SENDFILE_API,1,[Whether the solaris sendfile() API is available])
		AC_DEFINE(WITH_SENDFILE,1,[Whether to include sendfile() support])
	else
		AC_MSG_RESULT(no);
	fi
	;;

	*)
	;;
        esac
        ;;
  *)
    AC_MSG_RESULT(no)
    ;;
  esac ],
  AC_MSG_RESULT(yes)
)
# end check for sendfile support
#################################################

SMB_MODULE_MK(ntvfs_cifs, NTVFS, STATIC, ntvfs/config.mk)

SMB_MODULE_MK(ntvfs_simple, NTVFS, STATIC, ntvfs/config.mk)

SMB_MODULE_MK(ntvfs_print, NTVFS, STATIC, ntvfs/config.mk)

SMB_MODULE_MK(ntvfs_ipc, NTVFS, STATIC, ntvfs/config.mk)

SMB_MODULE_MK(ntvfs_posix, NTVFS, STATIC, ntvfs/config.mk)

SMB_MODULE_MK(ntvfs_nbench, NTVFS, STATIC, ntvfs/config.mk)

SMB_SUBSYSTEM_MK(NTVFS,ntvfs/config.mk)
