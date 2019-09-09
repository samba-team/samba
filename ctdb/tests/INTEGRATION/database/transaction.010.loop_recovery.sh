#!/bin/bash

test_info()
{
    cat <<EOF
Verify that the transaction_loop test succeeds with recoveries for replicated
databases.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.
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

ctdb_test_init

set -e

cluster_is_healthy

TESTDB="replicated_trans.tdb"

try_command_on_node 0 "$CTDB attach $TESTDB replicated"
try_command_on_node 0 "$CTDB wipedb $TESTDB"

try_command_on_node 0 "$CTDB listnodes | wc -l"
num_nodes="$out"

if [ -z "$CTDB_TEST_TIMELIMIT" ] ; then
    CTDB_TEST_TIMELIMIT=30
fi

t="$CTDB_TEST_WRAPPER $VALGRIND transaction_loop \
	-n ${num_nodes} -t ${CTDB_TEST_TIMELIMIT} \
	-D ${TESTDB} -T replicated -k testkey"

echo "Starting recovery loop"
recovery_loop_start

echo "Running transaction_loop on all $num_nodes nodes."
try_command_on_node -v -p all "$t"
