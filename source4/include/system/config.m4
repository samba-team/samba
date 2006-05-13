# filesys
AC_HEADER_DIRENT 
AC_CHECK_HEADERS(fcntl.h sys/fcntl.h sys/acl.h sys/resource.h sys/ioctl.h sys/mode.h sys/filio.h sys/fs/s5param.h sys/filsys.h )

# select
AC_CHECK_HEADERS(sys/select.h)

# time
AC_CHECK_HEADERS(sys/time.h utime.h)
AC_HEADER_TIME

# wait
AC_HEADER_SYS_WAIT
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

# capability
AC_CHECK_HEADERS(sys/capability.h)

# passwd
AC_CHECK_HEADERS(grp.h sys/id.h compat.h shadow.h sys/priv.h pwd.h sys/security.h)

# locale
AC_CHECK_HEADERS(ctype.h locale.h)

# glob
AC_CHECK_HEADERS(fnmatch.h)

# shmem
AC_CHECK_HEADERS(sys/ipc.h sys/mman.h sys/shm.h )

# terminal
AC_CHECK_HEADERS(termios.h termio.h sys/termio.h )
