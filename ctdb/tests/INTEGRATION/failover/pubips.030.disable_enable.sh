#!/bin/bash

test_info()
{
    cat <<EOF
Verify the operation of "ctdb disable" and "ctdb enable"
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init

########################################

set -e

cluster_is_healthy

select_test_node_and_ips

echo "Disabling node $test_node"
try_command_on_node 1 $CTDB disable -n $test_node
wait_until_node_has_status $test_node disabled 30 all
wait_until_node_has_no_ips "$test_node"

echo "Re-enabling node $test_node"
try_command_on_node 1 $CTDB enable -n $test_node
wait_until_node_has_status $test_node enabled 30 all
wait_until_node_has_some_ips "$test_node"
