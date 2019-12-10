#!/usr/bin/env bash

# Verify the operation of the 'ctdb ping' command
#
# 1. Run the 'ctdb ping' command on one of the nodes and verify that it
#    shows valid and expected output.
# 2. Shutdown one of the cluster nodes, using the 'ctdb shutdown'
#    command.
# 3. Run the 'ctdb ping -n <node>' command from another node to this
#    node.
# 4. Verify that the command is not successful since th ctdb daemon is
#    not running on the node.

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_init

try_command_on_node -v 0 "$CTDB ping -n 1"

sanity_check_output \
    1 \
    '^response from 1 time=-?[.0-9]+ sec[[:space:]]+\([[:digit:]]+ clients\)$'

ctdb_onnode -v 1 "shutdown"

wait_until_node_has_status 1 disconnected 30 0

try_command_on_node -v 0 "! $CTDB ping -n 1"

sanity_check_output \
    1 \
    "(: ctdb_control error: ('ctdb_control to disconnected node'|'node is disconnected')|Unable to get ping response from node 1|Node 1 is DISCONNECTED|ctdb_control for getpnn failed|: Can not access node. Node is not operational\.|Node 1 has status DISCONNECTED\|UNHEALTHY\|INACTIVE$)"
