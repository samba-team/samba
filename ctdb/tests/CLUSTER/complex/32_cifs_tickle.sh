#!/bin/bash

# Verify that CIFS connections are monitored and that CIFS tickles are sent.

# We create a connection to the CIFS server on a node and confirm that
# this connection is registered by CTDB.  Then disable the relevant CIFS
# server node and ensure that the takeover node sends an appropriate
# reset packet.

# Prerequisites:

# * An active CTDB cluster with at least 2 nodes with public addresses.

# * Test must be run on a real or virtual cluster rather than against
#   local daemons.

# * Test must not be run from a cluster node.

# * Clustered Samba must be listening on TCP port 445.

# Expected results:

# * CTDB should correctly record the connection and the takeover node
#   should send a reset packet.

. "${TEST_SCRIPTS_DIR}/cluster.bash"

set -e

ctdb_test_init

# We need this for later, so we know how long to sleep.
try_command_on_node 0 $CTDB getvar MonitorInterval
monitor_interval="${out#*= }"
#echo "Monitor interval on node $test_node is $monitor_interval seconds."

select_test_node_and_ips

test_port=445

echo "Connecting to node ${test_node} on IP ${test_ip}:${test_port} with netcat..."

sleep $((monitor_interval * 4)) | nc $test_ip $test_port &
nc_pid=$!
ctdb_test_exit_hook_add "kill $nc_pid >/dev/null 2>&1"

wait_until_get_src_socket "tcp" "${test_ip}:${test_port}" $nc_pid "nc"
src_socket="$out"
echo "Source socket is $src_socket"

# This should happen as soon as connection is up... but unless we wait
# we sometimes beat the registration.
echo "Checking if CIFS connection is tracked by CTDB on test node..."
wait_until 10 check_tickles $test_node $test_ip $test_port $src_socket

# This is almost immediate.  However, it is sent between nodes
# asynchonously, so it is worth checking...
echo "Wait until CIFS connection is tracked by CTDB on all nodes..."
try_command_on_node $test_node "$CTDB listnodes | wc -l"
numnodes="$out"
wait_until 5 \
    check_tickles_all $numnodes  $test_ip $test_port $src_socket
tcptickle_sniff_start $src_socket "${test_ip}:${test_port}"

echo "Disabling node $test_node"
try_command_on_node 1 $CTDB disable -n $test_node
wait_until_node_has_status $test_node disabled

tcptickle_sniff_wait_show
