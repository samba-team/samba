#!/usr/bin/env bash

# Verify that 'ctdb stop' causes a node to yield the recovery master role

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_init

leader_get 0

# leader set by leader_get()
# shellcheck disable=SC2154
echo "Stopping leader ${leader}..."
ctdb_onnode 1 stop -n "$leader"

wait_until_node_has_status "$leader" stopped

wait_until_leader_has_changed 0
