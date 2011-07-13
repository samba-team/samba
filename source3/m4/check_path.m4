dnl
dnl Samba3 build environment path checks
dnl
dnl Copyright (C) Michael Adam 2008
dnl
dnl Released under the GNU General Public License
dnl http://www.gnu.org/licenses/
dnl

AC_LIBREPLACE_LOCATION_CHECKS

m4_include(../dynconfig/config.m4)

#################################################
# set prefix for 'make test'
selftest_prefix="./st"
AC_SUBST(selftest_prefix)
AC_ARG_WITH(selftest-prefix,
[AS_HELP_STRING([--with-selftest-prefix=DIR], [The prefix where make test will be run ($selftest_prefix)])],
[ case "$withval" in
  yes|no)
    AC_MSG_WARN([--with-selftest-prefix called without argument - will use default])
  ;;
  * )
    selftest_prefix="$withval"
    ;;
  esac
])

#################################################
# set shrdir for 'make test'
selftest_shrdir=""
AC_SUBST(selftest_shrdir)
AC_ARG_WITH(selftest-shrdir,
[AS_HELP_STRING([--with-selftest-shrdir=DIR], [The share directory that make test will be run against ($selftest_shrdir)])],
[ case "$withval" in
  yes|no)
    AC_MSG_WARN([--with-selftest-shrdir called without argument - will use default])
  ;;
  * )
    selftest_shrdir="-s $withval"
    ;;
  esac
])

#################################################
# set path of samba4's smbtorture
smbtorture4_path=""
AC_SUBST(smbtorture4_path)
smbtorture4_option=""
AC_SUBST(smbtorture4_option)
AC_ARG_WITH(smbtorture4_path,
[AS_HELP_STRING([--with-smbtorture4-path=PATH], [The path to a samba4 smbtorture for make test (none)])],
[ case "$withval" in
  yes|no)
    AC_MSG_ERROR([--with-smbtorture4-path should take a path])
  ;;
  * )
    smbtorture4_path="$withval"
    if test -z "$smbtorture4_path" -a ! -f $smbtorture4_path; then
    	AC_MSG_ERROR(['$smbtorture_path' does not  exist!])
    fi
    smbtorture4_option="-t $withval"
  ;;
 esac
])

#################################################
# set custom conf for make test
selftest_custom_conf=""
AC_SUBST(selftest_custom_conf)
AC_ARG_WITH(selftest_custom_conf,
[AS_HELP_STRING([--with-selftest-custom-conf=PATH], [An optional custom smb.conf that is included in the server smb.conf during make test(none)])],
[ case "$withval" in
  yes|no)
    AC_MSG_ERROR([--with-selftest-custom-conf should take a path])
  ;;
  * )
    selftest_custom_conf="$withval"
    if test -z "$selftest_custom_conf" -a ! -f $selftest_custom_conf; then
	AC_MSG_ERROR(['$selftest_custom_conf' does not  exist!])
    fi
    selftest_custom_conf="-c $withval"
  ;;
 esac
])

## check for --enable-debug first before checking CFLAGS before
## so that we don't mix -O and -g
debug=no
AC_ARG_ENABLE(debug,
[AS_HELP_STRING([--enable-debug], [Turn on compiler debugging information (default=no)])],
    [if eval "test x$enable_debug = xyes"; then
	debug=yes
    fi])

AC_SUBST(developer)
developer=no
AC_ARG_ENABLE(developer, [AS_HELP_STRING([--enable-developer], [Turn on developer warnings and debugging (default=no)])],
    [if eval "test x$enable_developer = xyes"; then
        debug=yes
        developer=yes
    fi])

krb5developer=no
AC_ARG_ENABLE(krb5developer, [AS_HELP_STRING([--enable-krb5developer], [Turn on developer warnings and debugging, except -Wstrict-prototypes (default=no)])],
    [if eval "test x$enable_krb5developer = xyes"; then
        debug=yes
        developer=yes
	krb5_developer=yes
    fi])

picky_developer=no
AC_ARG_ENABLE(picky-developer, [AS_HELP_STRING([--enable-picky-developer], [Halt compilation on warnings])],
    [if eval "test x$enable_picky_developer = xyes"; then
        debug=yes
        developer=yes
        picky_developer=yes
    fi])

AC_ARG_WITH(cfenc,
[AS_HELP_STRING([--with-cfenc=HEADERDIR], [Use internal CoreFoundation encoding API for optimization (Mac OS X/Darwin only)])],
[
# May be in source $withval/CoreFoundation/StringEncodings.subproj.
# Should have been in framework $withval/CoreFoundation.framework/Headers.
for d in \
    $withval/CoreFoundation/StringEncodings.subproj \
    $withval/StringEncodings.subproj \
    $withval/CoreFoundation.framework/Headers \
    $withval/Headers \
    $withval
do
    if test -r $d/CFStringEncodingConverter.h; then
        ln -sfh $d include/CoreFoundation
    fi
done
])

