#!/bin/bash

test_info()
{
    cat <<EOF
Verify the operation of the 'ctdb stop' command.

* Verify that the status of the node changes to 'stopped'.

* Verify that the public IP addresses that were being served by
  the node are failed over to one of the other nodes.

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

echo "Stopping node ${test_node}..."
try_command_on_node 1 $CTDB stop -n $test_node
wait_until_node_has_status $test_node stopped
wait_until_ips_are_on_node '!' $test_node $test_node_ips
