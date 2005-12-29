AC_CACHE_CHECK([whether getpass should be replaced],samba_cv_REPLACE_GETPASS,[
SAVE_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="$CPPFLAGS -I${srcdir-.}/ -I${srcdir-.}/include -I${srcdir-.}/ubiqx -I${srcdir-.}/popt  -I${srcdir-.}/smbwrapper"
AC_TRY_COMPILE([
#define REPLACE_GETPASS 1
#define NO_CONFIG_H 1
#define main dont_declare_main
#include "${srcdir-.}/lib/cmdline/getsmbpass.c"
#undef main
],[],samba_cv_REPLACE_GETPASS=yes,samba_cv_REPLACE_GETPASS=no)
CPPFLAGS="$SAVE_CPPFLAGS"
])
if test x"$samba_cv_REPLACE_GETPASS" = x"yes"; then
	AC_DEFINE(REPLACE_GETPASS,1,[Whether getpass should be replaced])
fi
