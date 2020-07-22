#!/bin/bash

test_info()
{
    cat <<EOF
Verify that the transaction_loop test succeeds.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init

set -e

cluster_is_healthy

TESTDB="persistent_trans.tdb"

try_command_on_node 0 "$CTDB attach $TESTDB persistent"
try_command_on_node 0 "$CTDB wipedb $TESTDB"

try_command_on_node 0 "$CTDB listnodes | wc -l"
num_nodes="$out"

if [ -z "$CTDB_TEST_TIMELIMIT" ] ; then
    CTDB_TEST_TIMELIMIT=30
fi

t="$CTDB_TEST_WRAPPER $VALGRIND transaction_loop \
	-n ${num_nodes} -t ${CTDB_TEST_TIMELIMIT} \
	-D ${TESTDB} -T persistent -k testkey"

echo "Running transaction_loop on all $num_nodes nodes."
try_command_on_node -v -p all "$t"
