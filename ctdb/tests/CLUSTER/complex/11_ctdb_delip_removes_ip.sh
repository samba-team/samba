#!/bin/bash

# Verify that a node's public IP address can be deleted using 'ctdb deleteip'.

# This is an extended version of simple/17_ctdb_config_delete_ip.sh

. "${TEST_SCRIPTS_DIR}/cluster.bash"

set -e

test_node_has_test_ip()
{
	# $test_node and $test_ip set by select_test_node_and_ips()
	# shellcheck disable=SC2154
	try_command_on_node "$test_node" "ip addr show to ${test_ip}"
	[ -n "$out" ]
}

ctdb_test_init

select_test_node_and_ips

# $test_node and $test_ip set by select_test_node_and_ips()
# shellcheck disable=SC2154
echo "Checking that node ${test_node} hosts ${test_ip}..."
test_node_has_test_ip

echo "Attempting to remove ${test_ip} from node ${test_node}."
ctdb_onnode "$test_node" "delip ${test_ip}"
ctdb_onnode "$test_node" "ipreallocate"
wait_until_ips_are_on_node '!' "$test_node" "$test_ip"

echo "Waiting for ${test_ip} to disappear from node ${test_node}..."
wait_until 60/5 '!' test_node_has_test_ip

echo "GOOD: IP was successfully removed!"
