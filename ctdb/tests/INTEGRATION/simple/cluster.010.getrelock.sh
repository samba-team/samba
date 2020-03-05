#!/usr/bin/env bash

# Verify that "ctdb getreclock" gets the recovery lock correctly

# Make sure the recovery lock is consistent across all nodes.

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_init

echo "Check that recovery lock is set the same on all nodes..."
ctdb_onnode all getreclock

# outfile is set above by ctdb_onnode
# shellcheck disable=SC2154
n=$(sort -u "$outfile" | wc -l | tr -d '[:space:]')

case "$n" in
0) echo "GOOD: Recovery lock is unset on all nodes" ;;
1) echo "GOOD: All nodes have the same recovery lock setting" ;;
*) ctdb_test_fail "BAD: Recovery lock setting differs across nodes" ;;
esac
