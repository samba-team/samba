#!/bin/bash

test_info()
{
    cat <<EOF
Verify 'ctdb thaw' works correctly.

This is a superficial test that simply checks that 'ctdb statistics'
reports the node becomes unfrozen.  No checks are done to ensure that
client access to databases is unblocked.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. Use 'ctdb freeze -n <node>' to freeze the databases on one of the
   nodes.
3. Run 'ctdb statistics' to verify that 'frozen' has the value '1' on
   the node.
4, Now run 'ctdb thaw -n <node>' on the same node.
5. Run 'ctdb statistics' to verify that 'frozen' once again has the
   value '0' on the node.


Expected results:

* 'ctdb thaw' causes a node to 'thaw' and the status change can be
  seem via 'ctdb statistics'.
EOF
}

. ctdb_test_functions.bash

ctdb_test_init "$@"

set -e

onnode 0 $CTDB_TEST_WRAPPER cluster_is_healthy

test_node=1

echo "Freezing node $test_node"

try_command_on_node 0 $CTDB freeze -n $test_node

onnode 0 $CTDB_TEST_WRAPPER wait_until_node_has_status $test_node frozen

echo "That worked!  Now thawing node $test_node"

try_command_on_node 0 $CTDB thaw -n $test_node

onnode 0 $CTDB_TEST_WRAPPER wait_until_node_has_status $test_node unfrozen

ctdb_test_exit
