#!/bin/bash

test_info()
{
    cat <<EOF
Check that CTDB operates correctly if:

* DisableIPFailover is set; or
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

echo "Setting DisableIPFailover=1 on all nodes"
try_command_on_node all $CTDB setvar DisableIPFailover 1

echo "Getting \"before\" IP allocation..."
try_command_on_node -v any $CTDB ip all
before="$out"

echo "Disabling node ${test_node}..."
try_command_on_node "$test_node" $CTDB disable
wait_until_node_has_status $test_node disabled

echo "Getting \"after\" IP allocation..."
try_command_on_node -v any $CTDB ip all
after="$out"

if [ "$before" == "$after" ] ; then
	echo "GOOD: IP allocation is unchanged"
	echo
else
	die "BAD: IP allocation changed"
fi

echo "----------------------------------------"

daemons_stop

echo "Starting CTDB with an empty public addresses configuration..."
CTDB_PUBLIC_ADDRESSES="/dev/null" daemons_start

wait_until_ready

echo "Trying explicit ipreallocate..."
try_command_on_node any $CTDB ipreallocate

echo "Good, that seems to work!"
echo

ps_ctdbd
