#!/bin/bash

test_info()
{
    cat <<EOF
Verify that 'ctdb enablemonitor' works correctly.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.
* 00_ctdb_install_eventscript.sh successfully installed its event
  script.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. Disable monitoring on a node using 'ctdb disablemonitor -n <node>.
3. Create a file called /tmp/ctdb-test-unhealthy-trigger.<node> on the
   node.
4. Verify that the status of the node does not change to unhealthy
   within the interval indicated by the MonitorInterval variable,
   since monitoring is disabled.
5. Now enable monitoring on the node using 'ctdb enablemonitor -n <node>.
6. Verify that the status of the node changes to unhealthy within the
   interval indicated by the MonitorInterval variable.
7. Check that the file /tmp/ctdb-test-unhealthy-detected.<node> is
   created, indicating that the event script is the reason the node
   has been marked as unhealthy.

Expected results:

* When monitoring is enabled on a node, event scripts are executed and
  status changes are monitored.
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

try_command_on_node -v 0 $CTDB disablemonitor -n $test_node

sanity_check_output \
    1 \
    '^Monitoring mode:DISABLED$' \
    "$out"

onnode 0 $CTDB_TEST_WRAPPER wait_until_node_has_status $test_node monoff

trigger="/tmp/ctdb-test-unhealthy-trigger.${test_node}"
detected="/tmp/ctdb-test-unhealthy-detected.${test_node}"

recovered_flag="/tmp/ctdb-test-flag.recovered.${test_node}"
try_command_on_node $test_node touch "$recovered_flag"

ctdb_test_exit_hook="onnode $test_node rm -vf $trigger; restart_ctdb"

echo "Creating trigger file on node $test_node to see if it goes unhealthy..."
try_command_on_node $test_node touch "$trigger"

sleep_for $monitor_interval

try_command_on_node 0 $CTDB_TEST_WRAPPER node_has_status $test_node healthy

try_command_on_node $test_node test ! -e "$detected"

echo "OK: flag file was not created so monitoring must be disabled."

try_command_on_node -v 0 $CTDB enablemonitor -n $test_node

sanity_check_output \
    1 \
    '^Monitoring mode:ACTIVE$' \
    "$out"

onnode 0 $CTDB_TEST_WRAPPER wait_until_node_has_status $test_node monon

sleep_for $monitor_interval

try_command_on_node $test_node test -e "$detected"

echo "OK: flag file was created so monitoring must be enabled."

onnode 0 $CTDB_TEST_WRAPPER wait_until_node_has_status $test_node unhealthy $monitor_interval

try_command_on_node -v $test_node ls -l "$detected"

echo "OK, that all worked.  Expect a restart..."

ctdb_test_exit
