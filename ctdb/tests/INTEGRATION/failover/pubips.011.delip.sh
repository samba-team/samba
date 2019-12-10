#!/usr/bin/env bash

# Verify that a node's public IP address can be deleted using 'ctdb deleteip'

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_init

select_test_node_and_ips

echo "Deleting IP ${test_ip} from node ${test_node}"
try_command_on_node $test_node $CTDB delip $test_ip
try_command_on_node $test_node $CTDB ipreallocate
wait_until_ips_are_on_node '!' $test_node $test_ip
