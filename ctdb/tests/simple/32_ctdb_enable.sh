#!/bin/bash

test_info()
{
    cat <<EOF
Verify the operation of 'ctdb enable'.

After disabling a node...

* Verify that the status of a re-enabled node changes back to 'OK'.

* Verify that some public IP addreses are rebalanced to a re-enabled
  node.

This test does not do any network level checks to make sure IP
addresses are actually on interfaces.  It just consults "ctdb ip".
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init "$@"

########################################

set -e

cluster_is_healthy

select_test_node_and_ips

echo "Disabling node $test_node"
try_command_on_node 1 $CTDB disable -n $test_node
wait_until_node_has_status $test_node disabled
wait_until_node_has_no_ips "$test_node"

echo "Re-enabling node $test_node"
try_command_on_node 1 $CTDB enable -n $test_node
wait_until_node_has_status $test_node enabled
wait_until_node_has_some_ips "$test_node"
