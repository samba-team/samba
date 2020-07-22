#!/bin/bash

test_info()
{
    cat <<EOF
Verify that "ctdb getreclock" gets the recovery lock correctly.

Make sure the recovery lock is consistent across all nodes.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init

set -e

cluster_is_healthy

echo "Check that recovery lock is set the same on all nodes..."
try_command_on_node -v -q all $CTDB getreclock

if [ -z "$out" ] ; then
    echo "GOOD: Recovery lock is unset on all nodes"
    exit 0
fi

n=$(sort -u "$outfile" | wc -l)
if [ "$n" = 1 ] ; then
	echo "GOOD: All nodes have the same recovery lock setting"
else
	echo "BAD: Recovery lock setting differs across nodes"
	exit 1
fi
