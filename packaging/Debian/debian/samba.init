#!/bin/sh
#
# Start/stops the Samba daemons (nmbd and smbd).
#

PATH=/sbin:/bin:/usr/sbin:/usr/bin
DEBIAN_CONFIG=/etc/samba/debian_config

NMBDPID=/var/state/samba/nmbd.pid
SMBDPID=/var/state/samba/smbd.pid

# clear conflicting settings from the environment
unset TMPDIR

# Sanity check: see if Samba has been configured on this system.
if [ ! -f $DEBIAN_CONFIG ]; then
	echo "The file $DEBIAN_CONFIG does not exist! There is something wrong"
	echo "with the installation of Samba on this system. Please re-install"
	echo "Samba. I can't continue!!!"
	exit 1
fi

# Read current Samba configuration
. $DEBIAN_CONFIG

#       the Samba daemons.

# If Samba is running from inetd then there is nothing to do
if [ "$run_mode" = "from_inetd" ]; then
	# Commented out to close bug #26884 (startup message is rather long). I
	#	have yet to think how to let the user know that if he/she is running
	#	Samba from inetd, he can't just "/etc/init.d/samba stop" to stop
	#	the Samba daemons.
#	echo "Warning: Samba is not running as daemons. Daemons not restarted/stopped."
#	echo "Daemons will start automatically by inetd (if you wanted to start Samba)."
#	echo "If you want to stop Samba, get the PID's of all nmbd and smbd processes"
#	echo "and send them a SIGTERM signal but keep in mind that inetd could restart them."
	exit 0
fi

# See if the daemons are there
test -x /usr/sbin/nmbd -a -x /usr/sbin/smbd || exit 0

case "$1" in
	start)
		echo -n "Starting Samba daemons:"

		echo -n " nmbd"
		start-stop-daemon --start --quiet --exec /usr/sbin/nmbd -- -D

		echo -n " smbd"
		start-stop-daemon --start --quiet --exec /usr/sbin/smbd -- -D

		echo "."
		;;
	stop)
		echo -n "Stopping Samba daemons:"

		echo -n " nmbd"
		start-stop-daemon --stop --quiet --pidfile $NMBDPID

		echo -n " smbd"
		start-stop-daemon --stop --quiet --pidfile $SMBDPID

		echo "."
		;;
	reload)
		echo -n "Reloading /etc/samba/smb.conf (smbd only)"
		start-stop-daemon --stop --signal HUP --pidfile $SMBDPID

		echo "."
		;;
	restart|force-reload)
		echo -n "Restarting Samba daemons:"

		echo -n " nmbd"
		start-stop-daemon --stop --quiet --pidfile $NMBDPID
		sleep 2
		start-stop-daemon --start --quiet --exec /usr/sbin/nmbd -- -D

		echo -n " smbd"
		start-stop-daemon --stop --quiet --pidfile $SMBDPID
		sleep 2
		start-stop-daemon --start --quiet --exec /usr/sbin/smbd -- -D

		echo "."
		;;
	*)
		echo "Usage: /etc/init.d/samba {start|stop|reload|restart|force-reload}"
		exit 1
		;;
esac

exit 0
