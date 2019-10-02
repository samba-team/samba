#!/bin/bash

test_info()
{
    cat <<EOF
Verify that the recovery daemon handles unhosted IPs properly.

This test does not do any network level checks to make sure the IP
address is actually on an interface.  It just consults "ctdb ip".

This is a variation of the "addip" test.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init

set -e

cluster_is_healthy

select_test_node_and_ips

echo "Running test against node $test_node and IP $test_ip"

get_test_ip_mask_and_iface

echo "Deleting IP $test_ip from all nodes"
delete_ip_from_all_nodes $test_ip
try_command_on_node -v $test_node $CTDB ipreallocate
wait_until_ips_are_on_node ! $test_node $test_ip

try_command_on_node -v all $CTDB ip

my_exit_hook ()
{
    if ctdb_test_on_cluster ; then
	onnode -q all $CTDB event script enable legacy "10.interface"
    fi
}

ctdb_test_exit_hook_add my_exit_hook

# This forces us to wait until the ipreallocated associated with the
# delips is complete.
try_command_on_node $test_node $CTDB sync

# Wait for a monitor event.  Then the next steps are unlikely to occur
# in the middle of a monitor event and will have the expected effect.
wait_for_monitor_event $test_node

if ctdb_test_on_cluster ; then
    # Stop monitor events from bringing up the link status of an interface
    try_command_on_node $test_node $CTDB event script disable legacy 10.interface
fi

echo "Marking interface $iface down on node $test_node"
try_command_on_node $test_node $CTDB setifacelink $iface down

echo "Adding IP $test_ip to node $test_node"
try_command_on_node $test_node $CTDB addip $test_ip/$mask $iface
try_command_on_node $test_node $CTDB ipreallocate

echo "Wait long enough for IP verification to have taken place"
sleep_for 15

echo "Ensuring that IP ${test_ip} is not hosted on node ${test_node} when interface is down"
if ips_are_on_node '!' $test_node $test_ip; then
    echo "GOOD: the IP has not been hosted while the interface is down"
else
    echo "BAD: the IP is hosted but the interface is down"
    exit 1
fi

echo "Marking interface $iface up on node $test_node"
try_command_on_node $test_node $CTDB setifacelink $iface up
wait_until_ips_are_on_node $test_node $test_ip
