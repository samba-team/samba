#!/bin/bash

test_info()
{
    cat <<EOF
Verify 'ctdb freeze' works correctly.

This is a superficial test that simply checks that 'ctdb statistics'
reports the node becomes frozen.  No checks are done to ensure that
client access to databases is blocked.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. Use 'ctdb freeze -n <node>' to freeze the databases on one of the
   nodes.
3. Run 'ctdb statistics' to verify that 'frozen' has the value '1' on
   the node.

Expected results:

* When the database is frozen, the 'frozen' variable in the
  'ctdb statistics' output is set to 1 on the node.
EOF
}

. ctdb_test_functions.bash

ctdb_test_init "$@"

set -e

cluster_is_healthy

# Reset configuration
ctdb_restart_when_done

test_node=1

echo "Freezing node $test_node"

try_command_on_node 0 $CTDB freeze -n $test_node

wait_until_node_has_status $test_node frozen
