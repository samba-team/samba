#!/usr/bin/env bash

# Verify that an IP address can be added to a node using 'ctdb addip'

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_init

select_test_node_and_ips
get_test_ip_mask_and_iface

echo "Deleting IP $test_ip from all nodes"
delete_ip_from_all_nodes $test_ip
try_command_on_node -v $test_node $CTDB ipreallocate
wait_until_ips_are_on_node '!' $test_node $test_ip

# Debugging...
try_command_on_node -v all $CTDB ip

echo "Adding IP ${test_ip}/${mask} on ${iface}, node ${test_node}"
try_command_on_node $test_node $CTDB addip ${test_ip}/${mask} $iface
try_command_on_node $test_node $CTDB ipreallocate
wait_until_ips_are_on_node $test_node $test_ip
