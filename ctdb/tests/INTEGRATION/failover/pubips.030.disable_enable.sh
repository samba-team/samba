#!/usr/bin/env bash

# Verify the operation of "ctdb disable" and "ctdb enable"

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_init

########################################

select_test_node_and_ips

echo "Disabling node $test_node"
try_command_on_node 1 $CTDB disable -n $test_node
wait_until_node_has_status $test_node disabled 30 all
wait_until_node_has_no_ips "$test_node"

echo "Re-enabling node $test_node"
try_command_on_node 1 $CTDB enable -n $test_node
wait_until_node_has_status $test_node enabled 30 all
wait_until_node_has_some_ips "$test_node"
