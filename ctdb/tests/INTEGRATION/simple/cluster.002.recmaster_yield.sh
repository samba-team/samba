#!/usr/bin/env bash

# Verify that 'ctdb stop' causes a node to yield the recovery master role

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_init

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
