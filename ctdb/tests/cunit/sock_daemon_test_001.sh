#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

pidfile="${TEST_VAR_DIR}/sock_daemon_test.pid.$$"
sockpath="${TEST_VAR_DIR}/sock_daemon_test.sock.$$"

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
	    -e "s|PID ${_pid}|PID PID|" \
	    -e "s|\[${_pid}\]|[PID]|"
}


ok <<EOF
test1[PID]: listening on $sockpath
EOF
unit_test sock_daemon_test "$pidfile" "$sockpath" 1

ok <<EOF
test2[PID]: listening on $sockpath
test2[PID]: daemon started, pid=PID
test2[PID]: Received signal 1
test2[PID]: Received signal 10
test2[PID]: Received signal 15
test2[PID]: Shutting down
EOF
unit_test sock_daemon_test "$pidfile" "$sockpath" 2

ok <<EOF
test3[PID]: listening on $sockpath
test3[PID]: daemon started, pid=PID
test3[PID]: PID PID gone away, exiting
test3[PID]: Shutting down
EOF
unit_test sock_daemon_test "$pidfile" "$sockpath" 3

ok <<EOF
test4[PID]: daemon started, pid=PID
test4[PID]: Shutting down
EOF
unit_test sock_daemon_test "$pidfile" "$sockpath" 4

ok <<EOF
test5[PID]: listening on $sockpath
test5[PID]: daemon started, pid=PID
test5[PID]: Received signal 15
test5[PID]: Shutting down
EOF
unit_test sock_daemon_test "$pidfile" "$sockpath" 5

ok <<EOF
test6[PID]: listening on $sockpath
test6[PID]: daemon started, pid=PID
test6[PID]: Shutting down
EOF
unit_test sock_daemon_test "$pidfile" "$sockpath" 6
