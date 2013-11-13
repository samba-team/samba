#!/bin/bash

test_info()
{
    cat <<EOF
Verify the operation of the 'ctdb continue' command.

This is a superficial test of the 'ctdb continue' command.  It trusts
information from CTDB that indicates that the IP failover and failback
has happened correctly.  Another test should check that the failover
and failback has actually happened at the networking level.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. Stop one of the nodes using the 'ctdb stop' command.
3. Verify that the status of the node changes to 'stopped'.
4. Verify that the public IP addresses that were being served by
   the node are failed over to one of the other nodes.
5. Use 'ctdb continue' to bring the node back online.
6. Verify that the status of the node changes back to 'OK' and that
   some public IP addresses move back to the node.

Expected results:

* The 'ctdb continue' command successfully brings a stopped node online.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init "$@"

set -e

cluster_is_healthy

# Reset configuration
ctdb_restart_when_done

select_test_node_and_ips

echo "Stopping node ${test_node}..."
try_command_on_node 1 $CTDB stop -n $test_node

wait_until_node_has_status $test_node stopped

if wait_until_ips_are_on_nodeglob "[!${test_node}]" $test_node_ips ; then
    echo "All IPs moved."
else
    echo "Some IPs didn't move."
    testfailures=1
fi

echo "Continuing node $test_node"
try_command_on_node 1 $CTDB continue -n $test_node

wait_until_node_has_status $test_node notstopped

wait_until_node_has_some_ips "$test_node"
