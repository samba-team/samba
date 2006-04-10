AC_CHECK_HEADERS(linux/inotify.h asm/unistd.h)
AC_CHECK_FUNC(inotify_init)
AC_CHECK_DECL(__NR_inotify_init)

SMB_ENABLE(sys_notify_inotify, NO)

if test x"$ac_cv_func_inotify_init" = x"yes" -a x"$ac_cv_header_linux_inotify_h" = x"yes"; then
    SMB_ENABLE(sys_notify_inotify, YES)
fi

if test x"$ac_cv_header_linux_inotify_h" = x"yes" -a x"$ac_cv_have_decl___NR_inotify_init"; then
    SMB_ENABLE(sys_notify_inotify, YES)
fi
