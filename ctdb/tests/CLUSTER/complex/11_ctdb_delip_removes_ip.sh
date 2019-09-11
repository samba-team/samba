#!/bin/bash

# Verify that a node's public IP address can be deleted using 'ctdb deleteip'.

# This is an extended version of simple/17_ctdb_config_delete_ip.sh

. "${TEST_SCRIPTS_DIR}/cluster.bash"

set -e

ctdb_test_init

select_test_node_and_ips
get_test_ip_mask_and_iface

echo "Checking that node ${test_node} hosts ${test_ip}..."
try_command_on_node $test_node "ip addr show to ${test_ip} | grep -q ."

echo "Attempting to remove ${test_ip} from node ${test_node}."
try_command_on_node $test_node $CTDB delip $test_ip
try_command_on_node $test_node $CTDB ipreallocate
wait_until_ips_are_on_node '!' $test_node $test_ip

timeout=60
increment=5
count=0
echo "Waiting for ${test_ip} to disappear from node ${test_node}..."
while : ; do
    try_command_on_node -v $test_node "ip addr show to ${test_node}"
    if -n "$out" ; then
	echo "Still there..."
	if [ $(($count * $increment)) -ge $timeout ] ; then
	    echo "BAD: Timed out waiting..."
	    exit 1
	fi
	sleep_for $increment
	count=$(($count + 1))
    else
	break
    fi
done

echo "GOOD: IP was successfully removed!"
