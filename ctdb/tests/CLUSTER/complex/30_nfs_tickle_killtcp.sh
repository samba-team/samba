#!/bin/bash

# Verify that NFS connections are monitored and that NFS tickles are sent.

# Create a connection to the NFS server on a node. Then disable the
# relevant NFS server node and ensure that it sends an appropriate reset
# packet.  The packet must come from the releasing node.

# Prerequisites:

# * An active CTDB cluster with at least 2 nodes with public addresses.

# * Test must be run on a real or virtual cluster rather than against
#   local daemons.

# * Test must not be run from a cluster node.

# * Cluster nodes must be listening on the NFS TCP port (2049).

# Expected results:

# * CTDB on the releasing node should correctly send a reset packet when
#   the node is disabled.

. "${TEST_SCRIPTS_DIR}/cluster.bash"

set -e

ctdb_test_init

select_test_node_and_ips

test_port=2049

echo "Connecting to node ${test_node} on IP ${test_ip}:${test_port} with netcat..."

sleep 30 | nc $test_ip $test_port &
nc_pid=$!
ctdb_test_exit_hook_add "kill $nc_pid >/dev/null 2>&1"

wait_until_get_src_socket "tcp" "${test_ip}:${test_port}" $nc_pid "nc"
src_socket="$out"
echo "Source socket is $src_socket"

echo "Getting MAC address associated with ${test_ip}..."
releasing_mac=$(ip neigh show $test_prefix | awk '$4 == "lladdr" {print $5}')
[ -n "$releasing_mac" ] || die "Couldn't get MAC address for ${test_prefix}"
echo "MAC address is: ${releasing_mac}"

tcptickle_sniff_start $src_socket "${test_ip}:${test_port}"

echo "Disabling node $test_node"
try_command_on_node 1 $CTDB disable -n $test_node
wait_until_node_has_status $test_node disabled

# Only look for a reset from the releasing node
tcptickle_sniff_wait_show "$releasing_mac"
