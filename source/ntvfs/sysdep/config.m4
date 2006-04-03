AC_CHECK_HEADERS(linux/inotify.h asm/unistd.h)
AC_CHECK_FUNC(inotify_init)

SMB_ENABLE(ntvfs_inotify, NO)
if test x"$ac_cv_header_linux_inotify_h" = x"yes"; then
    SMB_ENABLE(ntvfs_inotify, YES)
fi
