#!/bin/bash

test_info()
{
    cat <<EOF
Verify the operation of 'ctdb detach' command.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. Attach test databases
3. Detach test databases
4. Verify that the databases are not attached.

Expected results:

* Command 'ctdb detach' command successfully removes attached databases.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init "$@"

set -e

cluster_is_healthy

# Reset configuration
ctdb_restart_when_done

######################################################################

# Confirm that no nodes have databases attached
check_no_db ()
{
    db="$1"
    try_command_on_node all $CTDB getdbmap
    local num_db=$(grep -c "$db" <<<"$out") || true
    if [ $num_db -eq 0 ]; then
	echo "GOOD: database $db is not attached any more"
    else
	echo "BAD: database $db is still attached"
	echo "$out"
	exit 1
    fi
}

######################################################################

testdb1="detach_test1.tdb"
testdb2="detach_test2.tdb"
testdb3="detach_test3.tdb"
testdb4="detach_test4.tdb"

echo "Create test databases"
echo "    $testdb1"
try_command_on_node 0 $CTDB attach $testdb1
echo "    $testdb2"
try_command_on_node 0 $CTDB attach $testdb2
echo "    $testdb3"
try_command_on_node 0 $CTDB attach $testdb3
echo "    $testdb4"
try_command_on_node 0 $CTDB attach $testdb4

######################################################################

echo "Detach single test database $testdb1"
try_command_on_node 1 $CTDB detach $testdb1

check_no_db $testdb1

######################################################################

echo "Detach multiple test databases"
echo "    $testdb2, $testdb3, $testdb4"
try_command_on_node 0 $CTDB detach $testdb2 $testdb3 $testdb4

check_no_db $testdb2
check_no_db $testdb3
check_no_db $testdb4
