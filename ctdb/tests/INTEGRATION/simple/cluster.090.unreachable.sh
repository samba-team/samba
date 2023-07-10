#!/usr/bin/env bash

# Verify an error occurs if a ctdb command is run against a node
# without a ctdbd

# That is, check that an error message is printed if an attempt is made
# to execute a ctdb command against a node that is not running ctdbd.

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_init

test_node=1

try_command_on_node 0 "$CTDB listnodes | wc -l"
num_nodes="$out"
echo "There are $num_nodes nodes."

echo "Shutting down node ${test_node}..."
try_command_on_node $test_node $CTDB shutdown

wait_until_node_has_status $test_node disconnected 30 0

wait_until_node_has_status 0 recovered 30 0

pat="ctdb_control error: 'ctdb_control to disconnected node'|ctdb_control error: 'node is disconnected'|Node $test_node is DISCONNECTED|Node $test_node has status DISCONNECTED\|UNHEALTHY\|INACTIVE"

for i in ip disable enable "ban 0" unban listvars ; do
    try_command_on_node -v 0 ! $CTDB $i -n $test_node

    if grep -Eq "$pat" "$outfile" ; then
	echo "OK: \"ctdb ${i}\" fails with expected \"disconnected node\" message"
    else
	echo "BAD: \"ctdb ${i}\" does not fail with expected \"disconnected node\" message"
	exit 1
    fi
done
