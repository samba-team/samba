#################################################
# Directory handling stuff to support both the
# legacy SAMBA directories and FHS compliant
# ones...
AC_PREFIX_DEFAULT(/usr/local/samba)

test x"${modulesdir}" = x"" && {
    modulesdir="\${exec_prefix}/modules"
}

BINDIR="${bindir}"
SBINDIR="${sbindir}"
LIBDIR="${libdir}"
LIBEXECDIR="${libexecdir}"
MANDIR="${mandir}"
DATADIR="${datadir}"
LOCALEDIR="${localedir}"
SCRIPTSBINDIR="${sbindir}"
#PYTHONDIR
#PYTHONARCHDIR

AC_ARG_ENABLE(fhs,
[AS_HELP_STRING([--enable-fhs], [Turn on FHS support (default=no)])])

if test x$enable_fhs != xyes; then
	MODULESDIR="${modulesdir}"
	INCLUDEDIR="${includedir}"
	SETUPDIR="${datadir}/setup"
	PKGCONFIGDIR="${libdir}/pkgconfig"
	SWATDIR="${datadir}/swat"
	CODEPAGEDIR="${datadir}/codepages"
	PAMMODULESDIR="${libdir}/security"
	CONFIGDIR="${sysconfdir}"
	PRIVATE_DIR="${prefix}/private"
	LOCKDIR="${localstatedir}/lock"
	PIDDIR="${localstatedir}/run"
	STATEDIR="${localstatedir}/locks"
	CACHEDIR="${localstatedir}/cache"
	LOGFILEBASE="${localstatedir}"
	SOCKET_DIR="${localstatedir}/run"
	PRIVILEGED_SOCKET_DIR="${localstatedir}/lib"
else
	AC_DEFINE(FHS_COMPATIBLE, 1, [Whether to use fully FHS-compatible paths])

	MODULESDIR="${modulesdir}/samba"
	INCLUDEDIR="${includedir}/samba-4.0"
	SETUPDIR="${datadir}/samba/setup"
	PKGCONFIGDIR="${libdir}/pkgconfig"
	SWATDIR="${datadir}/samba/swat"
	CODEPAGEDIR="${datadir}/samba/codepages"
	PAMMODULESDIR="${libdir}/security"
	CONFIGDIR="${sysconfdir}/samba"
	PRIVATE_DIR="${localstatedir}/lib/samba/private"
	LOCKDIR="${localstatedir}/lock/samba"
	PIDDIR="${localstatedir}/run/samba"
	STATEDIR="${localstatedir}/lib/samba"
	CACHEDIR="${localstatedir}/cache/samba"
	LOGFILEBASE="${localstatedir}/log/samba"
	SOCKET_DIR="${localstatedir}/run/samba"
	PRIVILEGED_SOCKET_DIR="${localstatedir}/lib/samba"
fi

AC_ARG_WITH(pammodulesdir,
[AS_HELP_STRING([--with-pammodulesdir=DIR],
 [Which directory to use for PAM modules ($libdir/security)])],
[ case "$withval" in
  yes|no)
  #
  # Just in case anybody calls it without argument
  #
    AC_MSG_WARN([--with-pammodulesdir called without argument - will use default])
  ;;
  * )
    PAMMODULESDIR="$withval"
  ;;
  esac])

AC_ARG_WITH(configdir,
[AS_HELP_STRING([--with-configdir=DIR],
 [Where to put configuration files ($sysconfdir)])],
[ case "$withval" in
  yes|no)
  #
  # Just in case anybody calls it without argument
  #
    AC_MSG_WARN([--with-configdir called without argument - will use default])
  ;;
  * )
    CONFIGDIR="$withval"
  ;;
  esac])

AC_ARG_WITH(privatedir,
[AS_HELP_STRING([--with-privatedir=DIR],
 [Where to put passdb.tdb and other private files ($prefix/private)])],
[ case "$withval" in
  yes|no)
  #
  # Just in case anybody calls it without argument
  #
    AC_MSG_WARN([--with-privatedir called without argument - will use default])
  ;;
  * )
    PRIVATE_DIR="$withval"
  ;;
  esac])

AC_ARG_WITH(lockdir,
[AS_HELP_STRING([--with-lockdir=DIR],
 [Where to put short term disposable state files ($localstatedir/lock)])],
[ case "$withval" in
  yes|no)
  #
  # Just in case anybody calls it without argument
  #
    AC_MSG_WARN([--with-lockdir called without argument - will use default])
  ;;
  * )
    LOCKDIR="$withval"
  ;;
  esac])

AC_ARG_WITH(piddir,
[AS_HELP_STRING([--with-piddir=DIR],
 [Where to put pid files ($localstatedir/run)])],
[ case "$withval" in
  yes|no)
  #
  # Just in case anybody calls it without argument
  #
    AC_MSG_WARN([--with-piddir called without argument - will use default])
  ;;
  * )
    PIDDIR="$withval"
  ;;
  esac])

AC_ARG_WITH(statedir,
[AS_HELP_STRING([--with-statedir=DIR],
 [Where to put persistent state files ($localstatedir/locks)])],
[ case "$withval" in
  yes|no)
  #
  # Just in case anybody calls it without argument
  #
    AC_MSG_WARN([--with-statedir called without argument - will use default])
  ;;
  * )
    STATEDIR="$withval"
  ;;
  esac])

AC_ARG_WITH(cachedir,
[AS_HELP_STRING([--with-cachedir=DIR],
 [Where to put temporary cache files ($localstatedir/cache)])],
[ case "$withval" in
  yes|no)
  #
  # Just in case anybody calls it without argument
  #
    AC_MSG_WARN([--with-cachedir called without argument - will use default])
  ;;
  * )
    CACHEDIR="$withval"
  ;;
  esac])

AC_ARG_WITH(logfilebase,
[AS_HELP_STRING([--with-logfilebase=DIR],
 [Where to put log files ($localstatedir)])],
[ case "$withval" in
  yes|no)
  #
  # Just in case anybody calls it without argument
  #
    AC_MSG_WARN([--with-logfilebase called without argument - will use default])
  ;;
  * )
    LOGFILEBASE="$withval"
  ;;
  esac])

AC_ARG_WITH(sockets-dir,
[AS_HELP_STRING([--with-sockets-dir=DIR],
 [socket directory ($localstatedir/run)])],
[ case "$withval" in
  yes|no)
  #
  # Just in case anybody calls it without argument
  #
    AC_MSG_WARN([--with-sockets-dir called without argument - will use default])
  ;;
  * )
    SOCKET_DIR="$withval"
  ;;
  esac])

AC_ARG_WITH(privileged-socket-dir,
[AS_HELP_STRING([--with-privileged-socket-dir=DIR],
 [privileged socket directory ($localstatedir/lib)])],
[ case "$withval" in
  yes|no)
  #
  # Just in case anybody calls it without argument
  #
    AC_MSG_WARN([--with-sockets-dir called without argument - will use default])
  ;;
  * )
    PRIVILEGED_SOCKET_DIR="$withval"
  ;;
  esac])

WINBINDD_SOCKET_DIR="${SOCKET_DIR}/winbindd"
WINBINDD_PRIVILEGED_SOCKET_DIR="${PRIVILEGED_SOCKET_DIR}/winbindd_privileged"
NMBDSOCKETDIR="${SOCKET_DIR}/nmbd"
NTP_SIGND_SOCKET_DIR="${SOCKET_DIR}/ntp_signd"
NCALRPCDIR="${SOCKET_DIR}/ncalrpc"
CONFIGFILE="${CONFIGDIR}/smb.conf"
LMHOSTSFILE="${CONFIGDIR}/lmhosts"
SMB_PASSWD_FILE="${PRIVATE_DIR}/smbpasswd"

AC_SUBST(BINDIR)
AC_SUBST(SBINDIR)
AC_SUBST(LIBDIR)
AC_SUBST(LIBEXECDIR)
AC_SUBST(MANDIR)
AC_SUBST(DATADIR)
AC_SUBST(LOCALEDIR)
AC_SUBST(SCRIPTSBINDIR)
dnl AC_SUBST(PYTHONDIR)
dnl AC_SUBST(PYTHONARCHDIR)
AC_SUBST(MODULESDIR)
AC_SUBST(INCLUDEDIR)
AC_SUBST(SETUPDIR)
AC_SUBST(PKGCONFIGDIR)
AC_SUBST(SWATDIR)
AC_SUBST(CODEPAGEDIR)
AC_SUBST(PAMMODULESDIR)
AC_SUBST(CONFIGDIR)
AC_SUBST(PRIVATE_DIR)
AC_SUBST(LOCKDIR)
AC_SUBST(PIDDIR)
AC_SUBST(STATEDIR)
AC_SUBST(CACHEDIR)
AC_SUBST(LOGFILEBASE)
AC_SUBST(SOCKET_DIR)
AC_SUBST(PRIVILEGED_SOCKET_DIR)
AC_SUBST(WINBINDD_SOCKET_DIR)
AC_SUBST(WINBINDD_PRIVILEGED_SOCKET_DIR)
AC_SUBST(NMBDSOCKETDIR)
AC_SUBST(NTP_SIGND_SOCKET_DIR)
AC_SUBST(NCALRPCDIR)
AC_SUBST(CONFIGFILE)
AC_SUBST(LMHOSTSFILE)
AC_SUBST(SMB_PASSWD_FILE)

