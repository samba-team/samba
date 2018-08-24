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

ctdb_test_init "$@"

set -e

cluster_is_healthy

if [ -z "$TEST_LOCAL_DAEMONS" ] ; then
	echo "SKIPPING this test - only runs against local daemons"
	exit 0
fi

# Reset configuration
ctdb_restart_when_done

select_test_node_and_ips

daemons_stop

echo "Starting CTDB with failover disabled..."
setup_ctdb --disable-failover
daemons_start

wait_until_ready

echo "Getting IP allocation..."
try_command_on_node -v any "$CTDB ip all | tail -n +2"

while read ip pnn ; do
	if [ "$pnn" != "-1" ] ; then
		die "BAD: IP address ${ip} is assigned to node ${pnn}"
	fi
done <<EOF
$out
EOF

echo "GOOD: All IP addresses are unassigned"

echo "----------------------------------------"
daemons_stop

echo "Starting CTDB with an empty public addresses configuration..."
setup_ctdb --no-public-addresses
daemons_start

wait_until_ready

echo "Trying explicit ipreallocate..."
try_command_on_node any $CTDB ipreallocate

echo "Good, that seems to work!"
echo

ps_ctdbd
