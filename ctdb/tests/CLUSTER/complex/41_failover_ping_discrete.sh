#!/bin/bash

# Verify that it is possible to ping a public address after disabling a node.

# We ping a public IP, disable the node hosting it and then ping the
# public IP again.

# Prerequisites:

# * An active CTDB cluster with at least 2 nodes with public addresses.

# * Test must be run on a real or virtual cluster rather than against
#   local daemons.

# * Test must not be run from a cluster node.

# Steps:

# 1. Verify that the cluster is healthy.
# 2. Select a public address and its corresponding node.
# 3. Send a single ping request packet to the selected public address.
# 4. Disable the selected node.
# 5. Send another single ping request packet to the selected public address.

# Expected results:

# * When a node is disabled the public address fails over and the
#   address is still pingable.

. "${TEST_SCRIPTS_DIR}/cluster.bash"

set -e

ctdb_test_init

select_test_node_and_ips

echo "Removing ${test_ip} from the local neighbor table..."
ip neigh flush "$test_prefix" >/dev/null 2>&1 || true

echo "Pinging ${test_ip}..."
ping_wrapper -q -n -c 1 $test_ip

gratarp_sniff_start

echo "Disabling node $test_node"
try_command_on_node 1 $CTDB disable -n $test_node
wait_until_node_has_status $test_node disabled

gratarp_sniff_wait_show

echo "Removing ${test_ip} from the local neighbor table again..."
ip neigh flush "$test_prefix" >/dev/null 2>&1 || true

echo "Pinging ${test_ip} again..."
ping_wrapper -q -n -c 1 $test_ip
