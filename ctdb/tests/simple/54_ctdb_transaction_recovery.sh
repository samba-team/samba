#!/bin/bash

test_info()
{
    cat <<EOF
Verify that the ctdb_transaction test succeeds.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. Run two copies of ctdb_transaction on each node with a 30 second
   timeout.
3. Ensure that all ctdb_transaction processes complete successfully.

Expected results:

* ctdb_transaction runs without error.
EOF
}

recovery_loop()
{
	local COUNT=1

	while true ; do
		echo Recovery $COUNT
		try_command_on_node 0 $CTDB recover
		sleep 2
		COUNT=$((COUNT + 1))
	done
}

recovery_loop_start()
{
	recovery_loop >/dev/null &
	RECLOOP_PID=$!
	ctdb_test_exit_hook_add "kill $RECLOOP_PID >/dev/null 2>&1"
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init "$@"

set -e

cluster_is_healthy

try_command_on_node 0 "$CTDB listnodes"
num_nodes=$(echo "$out" | wc -l)

if test "x${CTDB_TEST_TIMELIMIT}" == "x" ; then
	CTDB_TEST_TIMELIMIT=30
fi

t="$CTDB_TEST_WRAPPER $VALGRIND ctdb_transaction --timelimit=${CTDB_TEST_TIMELIMIT}"

echo "Starting recovery loop"
recovery_loop_start

echo "Running ctdb_transaction on all $num_nodes nodes."
try_command_on_node -v -p all "$t & $t"

