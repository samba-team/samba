#!/bin/bash

test_info()
{
    cat <<EOF
Verify the operation of 'ctdb attach' command.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. Shut down one of the nodes
3. Attach test databases
4. Start shutdown node
5. Verify that the databases are attached.
6. Restart one of the nodes
7. Verify that the databses are attached.


Expected results:

* Command 'ctdb attach' command successfully attaches databases.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init "$@"

set -e

cluster_is_healthy

# Reset configuration
ctdb_restart_when_done

######################################################################

try_command_on_node 0 "$CTDB listnodes -X"
listnodes_output="$out"
numnodes=$(wc -l <<<"$listnodes_output")
lastnode=$(( numnodes - 1 ))

######################################################################

# Confirm that the database is attached
check_db ()
{
    pnn="$1"
    db="$2"
    flag="$3"
    try_command_on_node $pnn "$CTDB getdbmap | grep $db"
    if [ -z "$out" ] ; then
	echo "BAD: database $db is not attached on node $node"
	echo "$out"
	exit 1
    else
	local flags=$(awk '{print $4}' <<<"$out") || true
	if [ "$flags" = "$flag" ]; then
	    echo "GOOD: database $db is attached on node $node with flag $flag"
	else
	    echo "BAD: database $db is attached on node $node with wrong flag"
	    echo "$out"
	    exit 1
	fi
    fi
}

######################################################################

testdb1="test_volatile.tdb"
testdb2="test_persistent.tdb"
testdb3="test_replicated.tdb"

test_node="0"

echo "Shutting down node $test_node"
stop_ctdb_1 "$test_node"
sleep 1
wait_until_node_has_status 1 recovered
try_command_on_node -v 1 $CTDB status

echo "Create test databases"
try_command_on_node 1 $CTDB attach "$testdb1"
try_command_on_node 1 $CTDB attach "$testdb2" persistent
try_command_on_node 1 $CTDB attach "$testdb3" replicated

echo
echo "Checking if database is attached with correct flags"
for node in $(seq 0 $lastnode) ; do
    if [ $node -ne $test_node ] ; then
	check_db $node $testdb1 ""
	check_db $node $testdb2 PERSISTENT
	check_db $node $testdb3 REPLICATED
    fi
done

######################################################################

echo
echo "Start node $test_node"
start_ctdb_1 "$test_node"
sleep 1
wait_until_ready

echo
echo "Checking if database is attached with correct flags"
check_db $test_node $testdb1 ""
check_db $test_node $testdb2 PERSISTENT
check_db $test_node $testdb3 REPLICATED

######################################################################

echo
echo "Restarting node $test_node"
restart_ctdb_1 "$test_node"
sleep 1
wait_until_ready

echo
echo "Checking if database is attached with correct flags"
check_db $test_node $testdb1 ""
check_db $test_node $testdb2 PERSISTENT
check_db $test_node $testdb3 REPLICATED
