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
2. On one of the cluster nodes, get the PID of a ctdb client.
3. Run 'ctdb process-exists <pid>' on the node and verify that the
   correct output is shown.
4. Run 'ctdb process-exists <pid>' with a pid of ctdb daemon
   process and verify that the correct output is shown.

Expected results:

* 'ctdb process-exists' shows the correct output.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init

set -e

cluster_is_healthy

test_node=1
srvid=0xAE00000012345678

# Execute a ctdb client on $test_node that will last for 60 seconds.
# It should still be there when we check.
try_command_on_node -v $test_node \
	"$CTDB_TEST_WRAPPER exec dummy_client -n 10 -S ${srvid} >/dev/null 2>&1 & echo \$!"
client_pid="$out"

cleanup ()
{
    if [ -n "$client_pid" ] ; then
	onnode $test_node kill -9 "$client_pid"
    fi
}

ctdb_test_exit_hook_add cleanup

echo "Waiting until PID $client_pid is registered on node $test_node"
status=0
wait_until 30 try_command_on_node $test_node \
	"$CTDB process-exists ${client_pid}" || status=$?
echo "$out"

if [ $status -eq 0 ] ; then
    echo "OK"
else
    die "BAD"
fi

echo "Checking for PID $client_pid with SRVID $srvid on node $test_node"
status=0
try_command_on_node $test_node \
	"$CTDB process-exists ${client_pid} ${srvid}" || status=$?
echo "$out"

if [ $status -eq 0 ] ; then
    echo "OK"
else
    die "BAD"
fi

echo "Checking for PID $client_pid with SRVID $client_pid on node $test_node"
try_command_on_node -v $test_node \
	"! $CTDB process-exists ${client_pid} ${client_pid}"

# Now just echo the PID of the ctdb daemon on test node.
# This is not a ctdb client and process-exists should return error.
try_command_on_node $test_node "ctdb getpid"
pid="$out"

echo "Checking for PID $pid on node $test_node"
try_command_on_node -v $test_node "! $CTDB process-exists ${pid}"
