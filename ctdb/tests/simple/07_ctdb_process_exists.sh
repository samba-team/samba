#!/bin/bash

. ctdb_test_functions.bash

set -e

onnode 0 $TEST_WRAP cluster_is_healthy

# Create a background process on node 2 that will last for 60 seconds.
try_command_on_node 2 'sleep 60 >/dev/null 2>&1 & echo $!'
pid="$out"

echo "Checking for PID $pid on node 2"
# set -e is good, but avoid it here
status=0
onnode 1 "ctdb process-exists 2:$pid" || status=$?
echo "$out"

if [ $status -eq 0 ] ; then
    echo "OK"
else
    echo "BAD"
    testfailures=1
fi

# Now just echo the PID of the shell from the onnode process on node
# 2.  This PID will disappear and PIDs shouldn't roll around fast
# enough to trick the test...  but there is a chance that will happen.
try_command_on_node 2 'echo $$'
pid="$out"

echo "Checking for PID $pid on node 2"
# set -e is good, but avoid it here
status=0
onnode 1 "ctdb process-exists 2:$pid" || status=$?
echo "$out"

if [ $status -ne 0 ] ; then
    echo "OK"
else
    echo "BAD"
    testfailures=1
fi

ctdb_test_exit
