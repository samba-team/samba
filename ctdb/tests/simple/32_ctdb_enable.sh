#!/bin/bash

test_info()
{
    cat <<EOF
Verify the operation of 'ctdb enable'.

This is a superficial test of the 'ctdb enable' command.  It trusts
information from CTDB that indicates that the IP failover has happened
correctly.  Another test should check that the failover has actually
happened at the networking level.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. Disable one of the nodes using 'ctdb disable -n <node>'.
3. Verify that the status of the node changes to 'disabled'.
4. Verify that the public IP addreses served by the disabled node are
   failed over to other nodes.
5. Enable the disabled node using 'ctdb enable -n '<node>'.
6. Verify that the status changes back to 'OK'.
7. Verify that some public IP addreses are failed back to the node.


Expected results:

* The status of a re-enabled node changes as expected and IP addresses
  fail back as expected.
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

if wait_until_ips_are_on_nodeglob "[!${test_node}]" $test_node_ips ; then
    echo "All IPs moved."
else
    echo "Some IPs didn't move."
    testfailures=1
fi

echo "Reenabling node $test_node"
try_command_on_node 1 $CTDB enable -n $test_node

wait_until_node_has_status $test_node enabled

wait_until_node_has_some_ips "$test_node"
