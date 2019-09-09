#!/bin/bash

test_info()
{
    cat <<EOF
Verify that a node's public IP address can be deleted using 'ctdb deleteip'.

This test does not do any network level checks to make sure IP
addresses are actually on interfaces.  It just consults "ctdb ip".
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init

set -e

cluster_is_healthy

select_test_node_and_ips

echo "Deleting IP ${test_ip} from node ${test_node}"
try_command_on_node $test_node $CTDB delip $test_ip
try_command_on_node $test_node $CTDB ipreallocate
wait_until_ips_are_on_node '!' $test_node $test_ip
