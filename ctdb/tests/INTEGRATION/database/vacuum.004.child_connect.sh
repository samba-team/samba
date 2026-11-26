#!/usr/bin/env bash

# Ensure that a vacuuming child exits if it can't connect to ctdbd
#
# A vacuuming child that failed to connect to its parent ctdbd used
# to continue running the parent's event loop.  The vacuuming timers
# of the other databases forked more such children, which ended up in
# a fork bomb when ctdbd exited right after forking a vacuuming child.

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_skip_on_cluster

ctdb_test_init

select_test_node

echo "Stall vacuuming on all other nodes"
ctdb_get_all_pnns
# all_pnns is set above
# shellcheck disable=SC2154
for pnn in $all_pnns; do
	if [ "$pnn" != "$test_node" ]; then
		ctdb_onnode "$pnn" "setvar VacuumInterval 99999"
	fi
done

# The vacuuming event is scheduled when attaching a database
echo "Setting VacuumInterval to 1 on node ${test_node}"
ctdb_onnode "$test_node" "setvar VacuumInterval 1"

ctdb_onnode "$test_node" getpid
# out is set above
# shellcheck disable=SC2154
ctdbd_pid="$out"
echo "ctdbd on node ${test_node} has PID ${ctdbd_pid}"

testprog_onnode "$test_node" "ctdb-path socket ctdbd"
socket="$out"
moved="${socket}.moved"

vacuum_children()
{
	# Ignore zombies, they have exited
	# shellcheck disable=SC2009
	ps -o stat=,args= --ppid "$ctdbd_pid" |
		grep -v '^Z' |
		grep 'ctdb_vacuum'
}

cleanup()
{
	if [ -e "$moved" ]; then
		mv "$moved" "$socket"
	fi
	pkill -KILL -P "$ctdbd_pid" -f 'ctdb_vacuum' || true
}
ctdb_test_exit_hook_add cleanup

# The only database with a vacuuming event that fires soon
testdb="vacuum_child_connect.tdb"
echo "Attaching database ${testdb}"
ctdb_onnode "$test_node" "attach ${testdb}"

ctdb_logs_checkpoint "$test_node"

# The ctdb tool reaches ctdbd via the moved socket.  The vacuuming
# child connects to the original socket path and fails.
echo "Moving ${socket} to ${moved}"
mv "$socket" "$moved"

msg="failed to switch vacuum daemon into client mode"
echo "Waiting for a vacuuming child on node ${test_node} to fail"
logged_msg()
{
	ctdb_logs_since_checkpoint "$test_node" | grep -q "$msg"
}
wait_until 30 logged_msg

echo "Stalling vacuuming on node ${test_node}"
try_command_on_node "$test_node" \
	"CTDB_SOCKET=${moved} ${CTDB} setvar VacuumInterval 99999"

echo "Moving ${moved} back to ${socket}"
mv "$moved" "$socket"

echo "Checking that the vacuuming child has exited"
if ! wait_until 10 ! vacuum_children; then
	vacuum_children || true
	ctdb_test_fail "Vacuuming child is still running"
fi
