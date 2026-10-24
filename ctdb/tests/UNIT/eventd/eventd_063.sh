#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "exit when the startup socket is closed"

# Want word splitting in $VALGRIND, eventd_* set in scripts/local.sh
# shellcheck disable=SC2086,SC2154
stdin_socket $VALGRIND ctdb-eventd >"$eventd_logfile" 2>&1 &
helper_pid=$!
# shellcheck disable=SC2154
wait_until 10 test -S "$eventd_socket" ||
	die "ctdb_eventd failed to start"
test_cleanup cleanup_eventd

kill -9 "$helper_pid"

# eventd isn't polling a PID, so it can only notice via the socket.
# Don't fail here, so the check below reports a failure.
# eventd_pidfile set in scripts/local.sh
# shellcheck disable=SC2154
wait_until 10 test ! -e "$eventd_pidfile" || true

ok_null
unit_test test ! -e "$eventd_pidfile"

# Only logged when the startup socket is closed
ok_null
unit_test grep -q "Parent gone away, exiting" "$eventd_logfile"
