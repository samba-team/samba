#################################################
# Check whether winbind is supported on this platform.  If so we need to
# build and install client programs, sbin programs and shared libraries

AC_MSG_CHECKING(whether to build winbind)

# Initially, the value of $host_os decides whether winbind is supported

case "$host_os" in
	*linux*|*irix*)
		HAVE_WINBIND=yes
		;;
	*solaris*)
		HAVE_WINBIND=yes
		WINBIND_NSS_EXTRA_OBJS="nsswitch/winbind_nss_solaris.o"
		WINBIND_NSS_EXTRA_LIBS="-lsocket"
		;;
	*hpux11*)
		HAVE_WINBIND=yes
		WINBIND_NSS_EXTRA_OBJS="nsswitch/winbind_nss_solaris.o"
		;;
	*)
		HAVE_WINBIND=no
		winbind_no_reason=", unsupported on $host_os"
		;;
esac

AC_SUBST(WINBIND_NSS_EXTRA_OBJS)
AC_SUBST(WINBIND_NSS_EXTRA_LIBS)

# Check the setting of --with-winbindd

AC_ARG_WITH(winbind,
[  --with-winbind          Build winbind (default, if supported by OS)],
[ 
  case "$withval" in
	yes)
		HAVE_WINBIND=yes
		;;
        no)
		HAVE_WINBIND=no
                winbind_reason=""
                ;;
  esac ],
)

# We need unix domain sockets for winbind
if test x"$HAVE_WINBIND" = x"yes"; then
	if test x"$samba_cv_unixsocket" = x"no"; then
		winbind_no_reason=", no unix domain socket support on $host_os"
		HAVE_WINBIND=no
	fi
fi

# Display test results

if test x"$HAVE_WINBIND" = x"yes"; then
        AC_MSG_RESULT(yes)
	AC_DEFINE(WITH_WINBIND,1,[Whether to build winbind])

	EXTRA_BIN_PROGS="$EXTRA_BIN_PROGS bin/wbinfo\$(EXEEXT)"
	EXTRA_SBIN_PROGS="$EXTRA_SBIN_PROGS bin/winbindd\$(EXEEXT)"
        if test x"$BLDSHARED" = x"true"; then
		case "$host_os" in
		*irix*)
			SHLIB_PROGS="$SHLIB_PROGS nsswitch/libns_winbind.so"
			;;
		*)
			SHLIB_PROGS="$SHLIB_PROGS nsswitch/libnss_winbind.so"
			;;
		esac
		if test x"$with_pam" = x"yes"; then
			SHLIB_PROGS="$SHLIB_PROGS nsswitch/pam_winbind.so"
		fi
	fi
else
        AC_MSG_RESULT(no$winbind_no_reason)
fi

# Solaris has some extra fields in struct passwd that need to be
# initialised otherwise nscd crashes.  Unfortunately autoconf < 2.50
# doesn't have the AC_CHECK_MEMBER macro which would be handy for checking
# this. 

#AC_CHECK_MEMBER(struct passwd.pw_comment,
#		AC_DEFINE(HAVE_PASSWD_PW_COMMENT, 1, [Defined if struct passwd has pw_comment field]),
#		[#include <pwd.h>])

AC_CACHE_CHECK([whether struct passwd has pw_comment],samba_cv_passwd_pw_comment, [
    AC_TRY_COMPILE([#include <pwd.h>],[struct passwd p; p.pw_comment;],
	samba_cv_passwd_pw_comment=yes,samba_cv_passwd_pw_comment=no)])
if test x"$samba_cv_passwd_pw_comment" = x"yes"; then
   AC_DEFINE(HAVE_PASSWD_PW_COMMENT,1,[Whether struct passwd has pw_comment])
fi

#AC_CHECK_MEMBER(struct passwd.pw_age,
#		AC_DEFINE(HAVE_PASSWD_PW_AGE, 1, [Defined if struct passwd has pw_age field]),
#		[#include <pwd.h>])

AC_CACHE_CHECK([whether struct passwd has pw_age],samba_cv_passwd_pw_age, [
    AC_TRY_COMPILE([#include <pwd.h>],[struct passwd p; p.pw_age;],
	samba_cv_passwd_pw_age=yes,samba_cv_passwd_pw_age=no)])
if test x"$samba_cv_passwd_pw_age" = x"yes"; then
   AC_DEFINE(HAVE_PASSWD_PW_AGE,1,[Whether struct passwd has pw_age])
fi
