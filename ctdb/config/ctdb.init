#!/bin/sh

# Start and stop CTDB (Clustered TDB daemon)
#
# chkconfig: - 90 01
#
# description: Starts and stops CTDB
# pidfile: /var/run/ctdb/ctdbd.pid
# config: /etc/sysconfig/ctdb

### BEGIN INIT INFO
# Provides:            ctdb
# Required-Start:      $local_fs $syslog $network $remote_fs
# Required-Stop:       $local_fs $syslog $network $remote_fs
# Default-Start:       2 3 4 5
# Default-Stop:        0 1 6
# Short-Description:   start and stop ctdb service
# Description:         Start and stop CTDB (Clustered TDB daemon)
### END INIT INFO

# Source function library.
if [ -f /etc/init.d/functions ] ; then
    # Red Hat
    . /etc/init.d/functions
elif [ -f /etc/rc.d/init.d/functions ] ; then
    # Red Hat
    . /etc/rc.d/init.d/functions
elif [ -f /etc/rc.status ] ; then
    # SUSE
    . /etc/rc.status
    rc_reset
    LC_ALL=en_US.UTF-8
elif [ -f /lib/lsb/init-functions ] ; then
    # Debian
    . /lib/lsb/init-functions
fi

# Avoid using root's TMPDIR
unset TMPDIR

[ -n "$CTDB_BASE" ] || export CTDB_BASE="/etc/ctdb"

. "${CTDB_BASE}/functions"
loadconfig "network"
loadconfig "ctdb"

# check networking is up (for redhat)
if [ "$NETWORKING" = "no" ] ; then
    exit 0
fi

detect_init_style
export CTDB_INIT_STYLE

ctdbd="${CTDBD:-/usr/sbin/ctdbd}"
ctdbd_wrapper="${CTDBD_WRAPPER:-/usr/sbin/ctdbd_wrapper}"
pidfile="${CTDB_PIDFILE:-/var/run/ctdb/ctdbd.pid}"

############################################################

start()
{
    echo -n "Starting ctdbd service: "

    case "$CTDB_INIT_STYLE" in
	suse)
	    startproc \
		"$ctdbd_wrapper" "$pidfile" "start"
	    rc_status -v
	    ;;
	redhat)
	    daemon --pidfile "$pidfile" \
		"$ctdbd_wrapper" "$pidfile" "start"
	    RETVAL=$?
	    echo
	    [ $RETVAL -eq 0 ] && touch /var/lock/subsys/ctdb || RETVAL=1
	    return $RETVAL
	    ;;
	debian)
	    eval start-stop-daemon --start --quiet --background --exec \
		"$ctdbd_wrapper" "$pidfile" "start"
	    ;;
    esac
}

stop()
{
    echo -n "Shutting down ctdbd service: "

    case "$CTDB_INIT_STYLE" in
	suse)
	    "$ctdbd_wrapper" "$pidfile" "stop"
	    rc_status -v
	    ;;
	redhat)
	    "$ctdbd_wrapper" "$pidfile" "stop"
	    RETVAL=$?
            [ $RETVAL -eq 0 ] && success || failure
	    echo ""
	    [ $RETVAL -eq 0 ] && rm -f /var/lock/subsys/ctdb
	    return $RETVAL
	    ;;
	debian)
	    "$ctdbd_wrapper" "$pidfile" "stop"
	    log_end_msg $?
	    ;;
    esac
}

restart()
{
    stop
    start
}

check_status ()
{
    # Backward compatibility.  When we arrange to pass --pidfile to
    # ctdbd we also create the directory that will contain it.  If
    # that directory is missing then we don't use the pidfile to check
    # status.  Note that this probably won't work if
    # $CTDB_VALGRIND="yes" but this doesn't need full backward
    # compatibility because it is a debug option.
    if [ -d $(dirname "$pidfile") ] ; then
	_pf_opt="-p $pidfile"
    else
	_pf_opt=""
    fi

    case "$CTDB_INIT_STYLE" in
	suse)
	    checkproc $_pf_opt "$ctdbd"
	    rc_status -v
	    ;;
	redhat)
	    status $_pf_opt -l "ctdb" "$ctdbd"
	    ;;
	debian)
	    status_of_proc $_pf_opt "$ctdbd" "ctdb"
	    ;;
    esac
}

############################################################

case "$1" in
    start)
  	start
	;;
    stop)
  	stop
	;;
    restart|reload|force-reload)
  	restart
	;;
    status)
  	check_status
	;;
    condrestart|try-restart)
  	if check_status >/dev/null ; then
	    restart
	fi
	;;
    cron)
	# used from cron to auto-restart ctdb
  	check_status >/dev/null 2>&1 || restart
	;;
    *)
	echo "Usage: $0 {start|stop|restart|reload|force-reload|status|cron|condrestart|try-restart}"
	exit 1
esac
