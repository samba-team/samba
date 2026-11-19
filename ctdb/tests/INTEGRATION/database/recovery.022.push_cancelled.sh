#!/usr/bin/env bash

# Test that unconfirmed DB pushes are cancelled

# A push is cancelled when the database is thawed without confirming
# the push, when it is replaced by a new push, when its transaction is
# cancelled, or when the database is detached.  Records pushed using a
# cancelled push must be ignored.  See db_push_test.c for details.

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_skip_on_cluster

ctdb_test_init

select_test_node

testdb="push_cancelled.tdb"
echo "Attaching database ${testdb}"
# test_node set by select_test_node() above
# shellcheck disable=SC2154
ctdb_onnode "$test_node" attach "$testdb"

ctdb_logs_checkpoint "$test_node"

echo "Running DB push test on node ${test_node}"
# Want word splitting in $VALGRIND
# shellcheck disable=SC2086
try_command_on_node -v "$test_node" \
	$CTDB_TEST_WRAPPER $VALGRIND db_push_test -D "$testdb" -k pushtest

node_log=$(ctdb_logs_since_checkpoint "$test_node")

msg="DB push already started for ${testdb}"
echo "Checking log on node ${test_node} for: ${msg}"
echo "$node_log" | grep -F "$msg"

msg="Cancelling DB push for ${testdb}"
echo "Checking log on node ${test_node} for 4 instances of: ${msg}"
n=$(echo "$node_log" | grep -cF "$msg") || true
if [ "$n" -ne 4 ]; then
	ctdb_test_fail "BAD: Found ${n} instances"
fi

msg="Failed to unmark"
echo "Checking log on node ${test_node} does not contain: ${msg}"
if echo "$node_log" | grep -F "$msg"; then
	ctdb_test_fail "BAD: Database unmarked when not marked"
fi
