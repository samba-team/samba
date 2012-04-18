#!/bin/bash

test_info()
{
    cat <<EOF
Verify that 'ctdb process-exists' shows correct information.

The implementation is creative about how it gets PIDs for existing and
non-existing processes.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. On one of the cluster nodes, get the PID of an existing process
   (using ps wax).
3. Run 'ctdb process-exists <pid>' on the node and verify that the
   correct output is shown.
4. Run 'ctdb process-exists <pid>' with a pid of a non-existent
   process and verify that the correct output is shown.

Expected results:

* 'ctdb process-exists' shows the correct output.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init "$@"

set -e

cluster_is_healthy

test_node=1

# Create a background process on $test_node that will last for 60 seconds.
# It should still be there when we check.
try_command_on_node $test_node 'sleep 60 >/dev/null 2>&1 & echo $!'
pid="$out"

echo "Checking for PID $pid on node $test_node"
# set -e is good, but avoid it here
status=0
onnode 0 "$CTDB process-exists ${test_node}:${pid}" || status=$?
echo "$out"

if [ $status -eq 0 ] ; then
    echo "OK"
else
    echo "BAD"
    testfailures=1
fi

# Now just echo the PID of the shell from the onnode process on node
# 2.  This PID will disappear and PIDs shouldn't roll around fast
# enough to trick the test...  but there is a chance that will happen!
try_command_on_node $test_node 'echo $$'
pid="$out"

echo "Checking for PID $pid on node $test_node"
try_command_on_node -v 0 "! $CTDB process-exists ${test_node}:${pid}"
