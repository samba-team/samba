dnl SMB Build Environment Path Checks
dnl -------------------------------------------------------
dnl  Copyright (C) Stefan (metze) Metzmacher 2004
dnl  Released under the GNU GPL
dnl -------------------------------------------------------
dnl

#################################################
# Directory handling stuff to support both the
# legacy SAMBA directories and FHS compliant
# ones...
AC_PREFIX_DEFAULT(/usr/local/samba)

AC_ARG_WITH(fhs, 
[  --with-fhs              Use FHS-compliant paths (default=no)],
    configdir="${sysconfdir}/samba"
    lockdir="\${VARDIR}/cache/samba"
    piddir="\${VARDIR}/run/samba"
    logfilebase="\${VARDIR}/log/samba"
    privatedir="\${CONFIGDIR}/private"
    libdir="\${prefix}/lib/samba"
    swatdir="\${DATADIR}/samba/swat",
    configdir="\${LIBDIR}"
    logfilebase="\${VARDIR}"
    lockdir="\${VARDIR}/locks"
    piddir="\${VARDIR}/locks"
    privatedir="\${prefix}/private"
    swatdir="\${prefix}/swat")

#################################################
# set private directory location
AC_ARG_WITH(privatedir,
[  --with-privatedir=DIR   Where to put smbpasswd ($ac_default_prefix/private)],
[ case "$withval" in
  yes|no)
  #
  # Just in case anybody calls it without argument
  #
    AC_MSG_WARN([--with-privatedir called without argument - will use default])
  ;;
  * )
    privatedir="$withval"
    ;;
  esac])

#################################################
# set lock directory location
AC_ARG_WITH(lockdir,
[  --with-lockdir=DIR      Where to put lock files ($ac_default_prefix/var/locks)],
[ case "$withval" in
  yes|no)
  #
  # Just in case anybody calls it without argument
  #
    AC_MSG_WARN([--with-lockdir called without argument - will use default])
  ;;
  * )
    lockdir="$withval"
    ;;
  esac])

#################################################
# set pid directory location
AC_ARG_WITH(piddir,
[  --with-piddir=DIR       Where to put pid files ($ac_default_prefix/var/locks)],
[ case "$withval" in
  yes|no)
  #
  # Just in case anybody calls it without argument
  #
    AC_MSG_WARN([--with-piddir called without argument - will use default])
  ;;
  * )
    piddir="$withval"
    ;;
  esac])

#################################################
# set configuration directory location
AC_ARG_WITH(configdir,
[  --with-configdir=DIR    Where to put configuration files (\$libdir)],
[ case "$withval" in
  yes|no)
  #
  # Just in case anybody does it
  #
    AC_MSG_WARN([--with-configdir called without argument - will use default])
  ;;
  * )
    configdir="$withval"
    ;;
  esac])

#################################################
# set log directory location
AC_ARG_WITH(logfilebase,
[  --with-logfilebase=DIR  Where to put log files (\$(VARDIR))],
[ case "$withval" in
  yes|no)
  #
  # Just in case anybody does it
  #
    AC_MSG_WARN([--with-logfilebase called without argument - will use default])
  ;;
  * )
    logfilebase="$withval"
    ;;
  esac])

AC_SUBST(configdir)
AC_SUBST(lockdir)
AC_SUBST(piddir)
AC_SUBST(logfilebase)
AC_SUBST(privatedir)
AC_SUBST(bindir)
AC_SUBST(sbindir)

debug=no
AC_ARG_ENABLE(debug, 
[  --enable-debug          Turn on compiler debugging information (default=no)],
    [if eval "test x$enable_debug = xyes"; then
        debug=yes
	CFLAGS="${CFLAGS} -g"
    fi])

developer=no
AC_ARG_ENABLE(developer, [  --enable-developer      Turn on developer warnings and debugging (default=no)],
    [if eval "test x$enable_developer = xyes"; then
        developer=yes
    	DEVELOPER_CFLAGS="-g -Wall -Wshadow -Werror-implicit-function-declaration -Wstrict-prototypes -Wpointer-arith -Wcast-qual -Wcast-align -Wwrite-strings -DDEBUG_PASSWORD -DDEVELOPER"
    fi])

AC_ARG_ENABLE(krb5developer, [  --enable-krb5developer  Turn on developer warnings and debugging, except -Wstrict-prototypes (default=no)],
    [if eval "test x$enable_krb5developer = xyes"; then
        developer=yes
	DEVELOPER_CFLAGS="-g -Wall -Wshadow -Wpointer-arith -Wcast-qual -Wcast-align -Wwrite-strings -DDEBUG_PASSWORD -DDEVELOPER"
    fi])

AC_ARG_ENABLE(gtkdeveloper, [  --enable-gtkdeveloper  Turn on developer warnings and debugging, except -Wstrict-prototypes and -Wshadow (default=no)],
    [if eval "test x$enable_gtkdeveloper = xyes"; then
        developer=yes
	DEVELOPER_CFLAGS="-g -Wall -Wpointer-arith -Wcast-qual -Wcast-align -Wwrite-strings -DDEBUG_PASSWORD -DDEVELOPER"
    fi])

experimental=no
AC_ARG_ENABLE(experimental, [  --enable-experimental Turn on experimental features (default=no)],
    [if eval "test x$enable_experimental = xyes"; then
        experimental=yes
    fi])



dnl exclude these modules 
AC_ARG_WITH(exclude-modules,
[  --with-exclude-modules=MODULES Comma-seperated list of names of modules to exclude from build],
[ if test $withval; then
	for i in `echo $withval | sed -e's/,/ /g'`
	do
		eval SMB_MODULE_$i=NOT
	done
fi ])

dnl Always built these modules shared
AC_ARG_WITH(shared-modules,
[  --with-shared-modules=MODULES  Comma-seperated list of names of modules to build shared],
[ if test $withval; then
	for i in `echo $withval | sed -e's/,/ /g'`
	do
		eval SMB_MODULE_$i=SHARED
	done
fi ])

dnl Always built these modules static
AC_ARG_WITH(static-modules,
[  --with-static-modules=MODULES  Comma-seperated list of names of modules to statically link in],
[ if test $withval; then
	for i in `echo $withval | sed -e's/,/ /g'`
	do
		eval SMB_MODULE_$i=STATIC
	done
fi ])
