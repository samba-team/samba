#!/bin/bash

test_info()
{
    cat <<EOF
Verify that 'ctdb stop' causes a node to yield the recovery master role.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Determine which node is the recmaster.
2. Stop this node using the 'ctdb stop' command.
3. Verify that the status of the node changes to 'stopped'.
4. Verify that this node no longer has the recovery master role.

Expected results:

* The 'ctdb stop' command causes a node to yield the recmaster role.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init "$@"

set -e

cluster_is_healthy

# Reset configuration
ctdb_restart_when_done

echo "Finding out which node is the recovery master..."
try_command_on_node -v 0 "$CTDB recmaster"
test_node=$out

echo "Stopping node ${test_node} - it is the current recmaster..."
try_command_on_node 1 $CTDB stop -n $test_node

wait_until_node_has_status $test_node stopped

echo "Checking which node is the recovery master now..."
try_command_on_node -v 0 "$CTDB recmaster"
recmaster=$out

if [ "$recmaster" != "$test_node" ] ; then
    echo "OK: recmaster moved to node $recmaster"
else
    echo "BAD: recmaster did not move"
    exit 1
fi
