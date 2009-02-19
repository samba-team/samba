#!/bin/bash

test_info()
{
    cat <<EOF
Verify that 'ctdb disablemonitor' works correctly.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.
* 00_ctdb_install_eventscript.sh successfully installed its event
  script.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. Create a file called /tmp/ctdb-test-unhealthy-trigger.<node> on a
   node and verify that the status of the node changes to unhealthy
   within the interval indicated by the MonitorInterval variable.
3. Check that the file /tmp/ctdb-test-unhealthy-detected.<node> is
   created, indicating that the event script is the reason the node
   has been marked as unhealthy.
4. Now disable monitoring on the node using 'ctdb disablemonitor -n <node>.
5. Verify that the message 'Monitoring mode:DISABLED' is printed.
6. Remove /tmp/ctdb-test-unhealthy-detected.<node> and ensure that it
   is not recreated within the interval indicated by the
   MonitorInterval variable.
7. Remove /tmp/ctdb-test-unhealthy-trigger.<node>.
8. Verify that the status of the node continues to be 'UNHEALTHY',
   since monitoring has been disabled.

Expected results:

* When monitoring is disabled, event scripts are not executed and the
  state of nodes is not monitored.
EOF
}

. ctdb_test_functions.bash

ctdb_test_init "$@"

set -e

onnode 0 $CTDB_TEST_WRAPPER cluster_is_healthy

test_node=1

# We need this for later, so we know how long to sleep.
try_command_on_node -v 0 $CTDB getvar MonitorInterval -n $test_node
monitor_interval="${out#*= }"
echo "Monitor interval on node $test_node is $monitor_interval seconds."

trigger="/tmp/ctdb-test-unhealthy-trigger.${test_node}"
detected="/tmp/ctdb-test-unhealthy-detected.${test_node}"

recovered_flag="/tmp/ctdb-test-flag.recovered.${test_node}"
try_command_on_node $test_node touch "$recovered_flag"

ctdb_test_exit_hook="onnode $test_node rm -vf $trigger"

echo "Creating trigger file on node $test_node to make it unhealthy..."
try_command_on_node $test_node touch "$trigger"

onnode 0 $CTDB_TEST_WRAPPER wait_until_node_has_status $test_node unhealthy $monitor_interval

try_command_on_node -v $test_node ls -l "$detected"

# Wait until recovery is complete before disabling monitoring,
# otherwise completion of the recover can turn monitoring back on!
echo "Waiting until recovery is complete..."
wait_until 30 onnode $test_node ! test -e "$recovered_flag"

try_command_on_node -v 0 $CTDB disablemonitor -n $test_node

sanity_check_output \
    1 \
    '^Monitoring mode:DISABLED$' \
    "$out"

onnode 0 $CTDB_TEST_WRAPPER wait_until_node_has_status $test_node monoff

try_command_on_node -v $test_node rm -v "$detected"

sleep_for $monitor_interval

try_command_on_node $test_node test ! -e "$detected"

echo "OK: flag file was not recreated so monitoring must be disabled."

echo "Removing trigger file.  Monitoring is disabled so node will stay unhealthy."

try_command_on_node -v $test_node rm -v "$trigger"

sleep_for $monitor_interval

onnode 0 $CTDB_TEST_WRAPPER node_has_status $test_node unhealthy

echo "OK, that all worked.  Expect a restart..."

ctdb_test_exit
