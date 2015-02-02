#!/bin/bash

test_info()
{
    cat <<EOF
Verify that "ctdb setrecmaster" sets the recovery lock correctly.

This test only does something when there is a recovery lock
configured.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init "$@"

set -e

cluster_is_healthy

# Reset configuration
ctdb_restart_when_done

get_generation ()
{
    local out
    try_command_on_node any $CTDB status
    generation=$(sed -n -e 's@^Generation:@@p' <<<"$out")
}

generation_has_changed ()
{
    local old_generation="$generation"
    get_generation
    [ "$old_generation" != "$generation" ]
}

wait_until_generation_has_changed ()
{
    echo
    echo "Wait until generation has changed..."
    wait_until 60 generation_has_changed
}

echo "Check that recovery lock is set the same on all nodes..."
try_command_on_node -v any $CTDB -n all getreclock
n=$(echo "$out" | sort -u | wc -l)
if [ "$n" = 1 ] ; then
    echo "GOOD: All nodes have the same recovery lock setting"
else
    echo "BAD: Recovery lock setting differs across nodes"
    exit 1
fi

echo
echo "Check that recovery lock is actually enabled..."
t=$(echo "$out" | sed -e 's@^Reclock file:@@' | sort -u)
if [ "$t" != "No reclock file used." ] ; then
    echo "OK: Recovery lock is set"
else
    echo "OOPS: Recovery lock is unset. Skipping remainder of test"
    exit 0
fi

echo
orig_reclock=$(sed -n -e '1s@^Reclock file:@@p' <<<"$out")
echo "Remember original recovery lock file: \"${orig_reclock}\""

echo
echo "Unset and test the recovery lock on all nodes..."
try_command_on_node any $CTDB -n all setreclock
try_command_on_node -v any $CTDB -n all getreclock
t=$(sort -u <<<"$out")
if [ "$t" = "No reclock file used." ] ; then
    echo "GOOD: Recovery lock unset on all nodes"
else
    echo "BAD: Recovery lock not unset on all nodes"
    exit 1
fi

echo
get_generation
echo "Current generation is ${generation}"

alt="${orig_reclock}.test"
echo
echo "Set alternative recovery lock (${alt}) and test on all nodes..."
try_command_on_node any $CTDB -n all setreclock "$alt"
try_command_on_node -v any $CTDB -n all getreclock
t=$(echo "$out" | sed -e 's@^Reclock file:@@' | sort -u)
if [ "$t" = "$alt" ] ; then
    echo "GOOD: Recovery lock set on all nodes"
else
    echo "BAD: Recovery lock not set on all nodes"
    try_command_on_node -v any rm -v "$alt" || true
    exit 1
fi

# Setting or updating the recovery lock file must cause a recovery
wait_until_generation_has_changed
echo "Current generation is ${generation}"

echo
echo "Restore and test the recovery lock on all nodes..."
try_command_on_node any $CTDB -n all setreclock "$orig_reclock"
try_command_on_node -v any rm -v "$alt"
try_command_on_node -v any $CTDB -n all getreclock
t=$(echo "$out" | sed -e 's@^Reclock file:@@' | sort -u)
if [ "$t" = "$orig_reclock" ] ; then
    echo "GOOD: Recovery lock restored on all nodes"
else
    echo "BAD: Recovery lock not restored on all nodes"
    exit 1
fi

wait_until_generation_has_changed
echo "Current generation is ${generation}"
