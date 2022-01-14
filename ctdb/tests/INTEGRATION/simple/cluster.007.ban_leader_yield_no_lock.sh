#!/usr/bin/env bash

# Verify that 'ctdb ban' causes a node to yield the leader role

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_skip_on_cluster

ctdb_test_init -n

ctdb_nodes_start_custom -C "cluster lock"

# This is the node used to execute commands
select_test_node
echo

# test_node set by select_test_node()
# shellcheck disable=SC2154
leader_get "$test_node"

# leader set by leader_get()
# shellcheck disable=SC2154
echo "Banning leader ${leader}..."
ctdb_onnode "$test_node" ban 300 -n "$leader"

wait_until_node_has_status "$leader" banned

wait_until_leader_has_changed "$test_node"
