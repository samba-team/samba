#!/bin/bash

test_info()
{
    cat <<EOF
Verify the operation of the 'ctdb stop' command.

This is a superficial test of the 'ctdb stop' command.  It trusts
information from CTDB that indicates that the IP failover has
happened correctly.  Another test should check that the failover
has actually happened at the networking level.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. Stop one of the nodes using the 'ctdb stop' command.
3. Verify that the status of the node changes to 'stopped'.
4. Verify that the public IP addresses that were being served by
   the node are failed over to one of the other nodes.

Expected results:

* The status of the stopped nodes changes as expected and IP addresses
  failover as expected.
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
