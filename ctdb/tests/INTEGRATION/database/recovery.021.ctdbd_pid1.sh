#!/usr/bin/env bash

# Test that recovery works when ctdbd is PID 1

# Restart a node with ctdbd as PID 1 in a new PID namespace, as in a
# container.  Lock helpers used to release their locks immediately
# when ctdbd was PID 1, so a frozen database was not locked.

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_skip_on_cluster

unshare_cmd="unshare -Urpf --mount-proc"
if ! $unshare_cmd true >/dev/null 2>&1; then
	ctdb_test_skip "SKIPPING this test - unable to create PID namespace"
fi

ctdb_test_init

select_test_node

# test_node set by select_test_node() above
# shellcheck disable=SC2154
echo "Restarting node ${test_node} with ctdbd as PID 1"
ctdb_nodes_stop "$test_node"
# ctdbd can't daemonize as PID 1, so run it in the background.
# --interactive logs to stderr, so append to the usual log file.
# Want CTDB_BASE expanded when executed under onnode
# shellcheck disable=SC2016
onnode "$test_node" \
	"exec ${unshare_cmd} ctdbd --interactive" \
	'>>"${CTDB_BASE}/log.ctdb" 2>&1 </dev/null' &
ctdb_test_exit_hook_add "ctdb_nodes_stop ${test_node} ; wait"
wait_until_ready

echo "Checking that ctdbd on node ${test_node} is PID 1"
ctdb_onnode "$test_node" getpid
# out set by ctdb_onnode() above
# shellcheck disable=SC2154
if [ "$out" != "1" ]; then
	ctdb_test_fail "ctdbd on node ${test_node} has PID ${out}"
fi

testdb="ctdbd_pid1.tdb"
echo "Attaching database ${testdb}"
ctdb_onnode "$test_node" attach "$testdb"

ctdb_logs_checkpoint "$test_node"

echo "Forcing recovery"
ctdb_onnode "$test_node" recover
wait_until_ready

echo "Checking that ctdbd on node ${test_node} is still running"
ctdb_onnode "$test_node" runstate

msg="Lock helper for database ${testdb} exited unexpectedly"
echo "Checking log on node ${test_node} does not contain: ${msg}"
if ctdb_logs_since_checkpoint "$test_node" | grep -F "$msg"; then
	ctdb_test_fail "Lock helper released lock early"
fi
