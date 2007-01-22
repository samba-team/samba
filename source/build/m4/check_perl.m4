dnl SMB Build Environment Perl Checks
dnl -------------------------------------------------------
dnl  Copyright (C) Stefan (metze) Metzmacher 2004
dnl  Released under the GNU GPL
dnl -------------------------------------------------------
dnl

case "$host_os" in
	*irix*)
		# On IRIX, we prefer Freeware or Nekoware Perl, because the
		# system perl is so ancient.
		AC_PATH_PROG(PERL, perl, "", "/usr/freeware/bin:/usr/nekoware/bin:$PATH")
		;;
	*)
		AC_PATH_PROG(PERL, perl)
		;;
esac

if test x"$PERL" = x""; then
	AC_MSG_WARN([No version of perl was found!])
	AC_MSG_ERROR([Please install perl from http://www.perl.com/])
fi
if test x"$debug" = x"yes";then
	PERL="$PERL -W"
fi
export PERL

AC_PATH_PROG(YAPP, yapp, false)
