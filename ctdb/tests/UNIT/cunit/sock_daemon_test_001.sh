#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

pidfile="${CTDB_TEST_TMP_DIR}/sock_daemon_test.pid.$$"
sockpath="${CTDB_TEST_TMP_DIR}/sock_daemon_test.sock.$$"

remove_files ()
{
	rm -f "$pidfile"
	rm -f "$sockpath"
}

test_cleanup remove_files

result_filter ()
{
	_pid="[0-9][0-9]*"
	sed -e "s|pid=${_pid}|pid=PID|" \
	    -e "s|PID ${_pid}|PID PID|"
}


ok <<EOF
daemon started, pid=PID
startup failed, ret=1
daemon started, pid=PID
startup failed, ret=2
daemon started, pid=PID
startup completed successfully
listening on $sockpath
Shutting down
EOF
unit_test sock_daemon_test "$pidfile" "$sockpath" 1

ok <<EOF
daemon started, pid=PID
startup completed successfully
listening on $sockpath
Received signal $(sigcode SIGUSR1)
reconfigure failed, ret=1
Received signal $(sigcode SIGUSR1)
reconfigure completed successfully
Received signal 1
reopen logs, ret=1
Received signal 1
reopen logs completed successfully
Received signal $(sigcode SIGTERM)
Shutting down
daemon started, pid=PID
startup completed successfully
listening on $sockpath
Received signal $(sigcode SIGUSR1)
reconfigure failed, ret=2
Received signal $(sigcode SIGUSR1)
reconfigure completed successfully
Received signal 1
reopen logs failed, ret=2
Received signal 1
reopen logs completed successfully
Received signal $(sigcode SIGTERM)
Shutting down
EOF
unit_test sock_daemon_test "$pidfile" "$sockpath" 2

ok <<EOF
daemon started, pid=PID
listening on $sockpath
PID PID gone away, exiting
Shutting down
EOF
unit_test sock_daemon_test "$pidfile" "$sockpath" 3

ok <<EOF
daemon started, pid=PID
Shutting down
EOF
unit_test sock_daemon_test "$pidfile" "$sockpath" 4

ok <<EOF
daemon started, pid=PID
listening on $sockpath
Received signal $(sigcode SIGTERM)
Shutting down
EOF
unit_test sock_daemon_test "$pidfile" "$sockpath" 5

ok <<EOF
daemon started, pid=PID
listening on $sockpath
Shutting down
EOF
unit_test sock_daemon_test "$pidfile" "$sockpath" 6

ok <<EOF
daemon started, pid=PID
startup completed successfully
Received signal $(sigcode SIGTERM)
Shutting down
EOF
unit_test sock_daemon_test "$pidfile" "$sockpath" 7

ok <<EOF
daemon started, pid=PID
startup completed successfully
Received signal $(sigcode SIGTERM)
Shutting down
daemon started, pid=PID
startup completed successfully
Received signal $(sigcode SIGTERM)
Shutting down
EOF
unit_test sock_daemon_test "$pidfile" "$sockpath" 8

ok <<EOF
daemon started, pid=PID
startup completed successfully
Received signal $(sigcode SIGTERM)
Shutting down
daemon started, pid=PID
startup completed successfully
Received signal $(sigcode SIGTERM)
Shutting down
EOF
unit_test sock_daemon_test "$pidfile" "$sockpath" 9

ok <<EOF
daemon started, pid=PID
listening on $sockpath
daemon started, pid=PID
listening on $sockpath
Received signal $(sigcode SIGTERM)
Shutting down
EOF
unit_test sock_daemon_test "$pidfile" "$sockpath" 10
