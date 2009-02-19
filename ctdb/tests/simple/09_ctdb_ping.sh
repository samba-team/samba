#!/bin/bash

test_info()
{
    cat <<EOF
Verify the operation of the 'ctdb ping' command.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. Run the 'ctdb ping' command on one of the nodes and verify that it
   shows valid and expected output. 
3. Shutdown one of the cluster nodes, using the 'ctdb shutdown'
   command. 
4. Run the 'ctdb ping -n <node>' command from another node to this
   node. 
5. Verify that the command is not successful since th ctdb daemon is
   not running on the node.

Expected results:

* The 'ctdb ping' command shows valid and expected output.
EOF
}

. ctdb_test_functions.bash

ctdb_test_init "$@"

set -e

onnode 0 $CTDB_TEST_WRAPPER cluster_is_healthy

try_command_on_node -v 0 "$CTDB ping -n 1"

sanity_check_output \
    1 \
    '^response from 1 time=[.0-9]+ sec[[:space:]]+\([[:digit:]]+ clients\)$' \
    "$out"

try_command_on_node 0 "$CTDB shutdown -n 1"

onnode 0 $CTDB_TEST_WRAPPER wait_until_node_has_status 1 disconnected

try_command_on_node -v 0 "! $CTDB ping -n 1"

sanity_check_output \
    1 \
    "(: ctdb_control error: 'ctdb_control to disconnected node'|Unable to get ping response from node 1|Node 1 is DISCONNECTED)" \
    "$out"

echo "Expect a restart..."

ctdb_test_exit
