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
        selftest=yes
    fi])

AC_SUBST(selftest)
selftest=no
AC_ARG_ENABLE(selftest, [AS_HELP_STRING([--enable-selftest], [Turn on selftest capability (default=no)])],
    [if eval "test x$enable_selftest = xyes"; then
        debug=yes
        selftest=yes
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

