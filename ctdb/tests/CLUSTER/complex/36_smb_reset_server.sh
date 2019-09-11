#!/bin/bash

# Verify that the server end of an SMB connection is correctly reset

# Prerequisites:

# * An active CTDB cluster with at least 2 nodes with public addresses.

# * Test must be run on a real or virtual cluster rather than against
#   local daemons.

# * Test must not be run from a cluster node.

# * Clustered Samba must be listening on TCP port 445.

# Expected results:

# * CTDB should correctly record the connection and the releasing node
#   should reset the server end of the connection.

. "${TEST_SCRIPTS_DIR}/cluster.bash"

set -e

ctdb_test_init

# We need this for later, so we know how long to sleep.
try_command_on_node 0 $CTDB getvar MonitorInterval
monitor_interval="${out#*= }"

select_test_node_and_ips

test_port=445

echo "Set NoIPTakeover=1 on all nodes"
try_command_on_node all $CTDB setvar NoIPTakeover 1

echo "Give the recovery daemon some time to reload tunables"
sleep_for 5

echo "Connecting to node ${test_node} on IP ${test_ip}:${test_port} with nc..."

sleep $((monitor_interval * 4)) | nc $test_ip $test_port &
nc_pid=$!
ctdb_test_exit_hook_add "kill $nc_pid >/dev/null 2>&1"

wait_until_get_src_socket "tcp" "${test_ip}:${test_port}" $nc_pid "nc"
src_socket="$out"
echo "Source socket is $src_socket"

# This should happen as soon as connection is up... but unless we wait
# we sometimes beat the registration.
echo "Waiting until SMB connection is tracked by CTDB on test node..."
wait_until 10 check_tickles $test_node $test_ip $test_port $src_socket

# It would be nice if ss consistently used local/peer instead of src/dst
ss_filter="src ${test_ip}:${test_port} dst ${src_socket}"

try_command_on_node $test_node \
		    "ss -tn state established '${ss_filter}' | tail -n +2"
if [ -z "$out" ] ; then
	echo "BAD: ss did not list the socket"
	exit 1
fi
echo "GOOD: ss lists the socket:"
cat "$outfile"

echo "Disabling node $test_node"
try_command_on_node 1 $CTDB disable -n $test_node
wait_until_node_has_status $test_node disabled

try_command_on_node $test_node \
		    "ss -tn state established '${ss_filter}' | tail -n +2"
if [ -n "$out" ] ; then
	echo "BAD: ss listed the socket after failover"
	exit 1
fi
echo "GOOD: ss no longer lists the socket"
