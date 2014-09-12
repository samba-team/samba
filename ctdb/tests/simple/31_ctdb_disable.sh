#!/bin/bash

test_info()
{
    cat <<EOF
Verify the operation of 'ctdb disable'.

* Verify that the status of the node changes to 'disabled'.

* Verify that the IP addreses served by the disabled node are failed
  over to other nodes.

This test does not do any network level checks to make sure IP
addresses are actually on interfaces.  It just consults "ctdb ip".
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init "$@"

set -e

cluster_is_healthy

# Reset configuration
ctdb_restart_when_done

select_test_node_and_ips

echo "Disabling node $test_node"
try_command_on_node 1 $CTDB disable -n $test_node
wait_until_node_has_status $test_node disabled
wait_until_ips_are_on_node '!' $test_node $test_node_ips
