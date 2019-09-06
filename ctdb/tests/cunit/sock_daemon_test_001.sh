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
	    -e "s|PID ${_pid}|PID PID|" \
	    -e "s|\[${_pid}\]|[PID]|"
}


ok <<EOF
test1[PID]: daemon started, pid=PID
test1[PID]: startup failed, ret=1
test1[PID]: daemon started, pid=PID
test1[PID]: startup failed, ret=2
test1[PID]: daemon started, pid=PID
test1[PID]: startup completed successfully
test1[PID]: listening on $sockpath
test1[PID]: Shutting down
EOF
unit_test sock_daemon_test "$pidfile" "$sockpath" 1

ok <<EOF
test2[PID]: daemon started, pid=PID
test2[PID]: startup completed successfully
test2[PID]: listening on $sockpath
test2[PID]: Received signal $(sigcode SIGHUP)
test2[PID]: reconfigure failed, ret=1
test2[PID]: Received signal $(sigcode SIGUSR1)
test2[PID]: reconfigure completed successfully
test2[PID]: Received signal $(sigcode SIGTERM)
test2[PID]: Shutting down
test2[PID]: daemon started, pid=PID
test2[PID]: startup completed successfully
test2[PID]: listening on $sockpath
test2[PID]: Received signal $(sigcode SIGUSR1)
test2[PID]: reconfigure failed, ret=2
test2[PID]: Received signal $(sigcode SIGHUP)
test2[PID]: reconfigure completed successfully
test2[PID]: Received signal $(sigcode SIGTERM)
test2[PID]: Shutting down
EOF
unit_test sock_daemon_test "$pidfile" "$sockpath" 2

ok <<EOF
test3[PID]: daemon started, pid=PID
test3[PID]: listening on $sockpath
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
test5[PID]: daemon started, pid=PID
test5[PID]: listening on $sockpath
test5[PID]: Received signal $(sigcode SIGTERM)
test5[PID]: Shutting down
EOF
unit_test sock_daemon_test "$pidfile" "$sockpath" 5

ok <<EOF
test6[PID]: daemon started, pid=PID
test6[PID]: listening on $sockpath
test6[PID]: Shutting down
EOF
unit_test sock_daemon_test "$pidfile" "$sockpath" 6

ok <<EOF
test7[PID]: daemon started, pid=PID
test7[PID]: startup completed successfully
test7[PID]: Received signal $(sigcode SIGTERM)
test7[PID]: Shutting down
EOF
unit_test sock_daemon_test "$pidfile" "$sockpath" 7

ok <<EOF
test8[PID]: daemon started, pid=PID
test8[PID]: startup completed successfully
test8[PID]: Received signal $(sigcode SIGTERM)
test8[PID]: Shutting down
test8[PID]: daemon started, pid=PID
test8[PID]: startup completed successfully
test8[PID]: Received signal $(sigcode SIGTERM)
test8[PID]: Shutting down
EOF
unit_test sock_daemon_test "$pidfile" "$sockpath" 8

ok <<EOF
test9[PID]: daemon started, pid=PID
test9[PID]: startup completed successfully
test9[PID]: Received signal $(sigcode SIGTERM)
test9[PID]: Shutting down
test9[PID]: daemon started, pid=PID
test9[PID]: startup completed successfully
test9[PID]: Received signal $(sigcode SIGTERM)
test9[PID]: Shutting down
EOF
unit_test sock_daemon_test "$pidfile" "$sockpath" 9

ok <<EOF
test10[PID]: daemon started, pid=PID
test10[PID]: listening on $sockpath
test10[PID]: daemon started, pid=PID
test10[PID]: listening on $sockpath
test10[PID]: Received signal $(sigcode SIGTERM)
test10[PID]: Shutting down
EOF
unit_test sock_daemon_test "$pidfile" "$sockpath" 10
