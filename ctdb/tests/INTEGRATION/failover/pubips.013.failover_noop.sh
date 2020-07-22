#!/bin/bash

test_info()
{
    cat <<EOF
Check that CTDB operates correctly if:

* failover is disabled; or
* there are 0 public IPs configured

This test only does anything with local daemons.  On a real cluster it
has no way of updating configuration.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_skip_on_cluster

echo "Starting CTDB with failover disabled..."
ctdb_test_init -F

cluster_is_healthy

echo "Getting IP allocation..."
try_command_on_node -v any "$CTDB ip all | tail -n +2"

while read ip pnn ; do
	if [ "$pnn" != "-1" ] ; then
		die "BAD: IP address ${ip} is assigned to node ${pnn}"
	fi
done <"$outfile"

echo "GOOD: All IP addresses are unassigned"

echo "----------------------------------------"

echo "Starting CTDB with an empty public addresses configuration..."
ctdb_test_init -P /dev/null

cluster_is_healthy

echo "Trying explicit ipreallocate..."
try_command_on_node any $CTDB ipreallocate

echo "Good, that seems to work!"
echo
