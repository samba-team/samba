#!/usr/bin/env bash

# Verify that nothing bad occurs if a node stalls and the leader
# broadcast timeout triggers

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_init

select_test_node
echo

echo 'Get "leader timeout":'
conf_tool="${CTDB_SCRIPTS_HELPER_BINDIR}/ctdb-config"
# shellcheck disable=SC2154
# $test_node set by select_test_node() above
try_command_on_node "$test_node" "${conf_tool} get cluster 'leader timeout'"
# shellcheck disable=SC2154
# $out set by ctdb_onnode() above
leader_timeout="$out"
echo "Leader timeout is ${leader_timeout} seconds"
echo

# Assume leader timeout is reasonable and doesn't cause node to be
# disconnected
stall_time=$((leader_timeout * 2))

generation_get "$test_node"

echo "Get ctdbd PID on node ${test_node}..."
ctdb_onnode -v "$test_node" "getpid"
ctdbd_pid="$out"
echo

echo "Sending SIGSTOP to ctdbd on ${test_node}"
try_command_on_node "$test_node" "kill -STOP ${ctdbd_pid}"

sleep_for "$stall_time"

echo "Sending SIGCONT to ctdbd on ${test_node}"
try_command_on_node "$test_node" "kill -CONT ${ctdbd_pid}"
echo

wait_until_generation_has_changed "$test_node"

cluster_is_healthy
