#!/usr/bin/env bash

# Check that CTDB operates correctly if:

# * failover is disabled; or
# * there are 0 public IPs configured

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_skip_on_cluster

ctdb_test_init -n

echo "Starting CTDB with failover disabled..."
ctdb_nodes_start_custom -F

select_test_node

echo "Getting IP allocation..."

# $test_node set above by select_test_node()
# shellcheck disable=SC2154
try_command_on_node -v "$test_node" "$CTDB ip all | tail -n +2"

while read ip pnn ; do
	if [ "$pnn" != "-1" ] ; then
		die "BAD: IP address ${ip} is assigned to node ${pnn}"
	fi
done <"$outfile"

echo "GOOD: All IP addresses are unassigned"

echo "----------------------------------------"

echo "Starting CTDB with an empty public addresses configuration..."
ctdb_nodes_start_custom -P /dev/null

echo "Trying explicit ipreallocate..."
ctdb_onnode "$test_node" ipreallocate

echo "Good, that seems to work!"
echo
