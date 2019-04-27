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

ctdb_test_init

set -e

cluster_is_healthy

######################################################################

try_command_on_node 0 "$CTDB listnodes -X | wc -l"
numnodes="$out"

######################################################################

# Confirm that the database is attached
check_db_once ()
{
	local db="$1"

	local num_db

	try_command_on_node all "$CTDB getdbmap"
	num_db=$(grep -cF "name:${db}" "$outfile") || true
	if [ "$num_db" -eq "$numnodes" ]; then
		return 0
	else
		return 1
	fi
}

check_db ()
{
	local db="$1"

	echo "Waiting until database ${db} is attached on all nodes"
	wait_until 10 check_db_once "$db"
}

# Confirm that no nodes have databases attached
check_no_db_once ()
{
	local db="$1"

	local num_db

	try_command_on_node all "$CTDB getdbmap"
	num_db=$(grep -cF "name:${db}" "$outfile") || true
	if [ "$num_db" -eq 0 ]; then
		return 0
	else
		return 1
	fi
}

check_no_db ()
{
	local db="$1"

	echo "Waiting until database ${db} is detached on all nodes"
	wait_until 10 check_no_db_once "$db"
}

######################################################################

testdb1="detach_test1.tdb"
testdb2="detach_test2.tdb"
testdb3="detach_test3.tdb"
testdb4="detach_test4.tdb"

echo "Create test databases"
for db in "$testdb1" "$testdb2" "$testdb3" "$testdb4" ; do
    echo "  $db"
    try_command_on_node 0 $CTDB attach "$db"
done

for db in "$testdb1" "$testdb2" "$testdb3" "$testdb4" ; do
    check_db "$db"
done

######################################################################

echo
echo "Ensuring AllowClientDBAttach=1 on all nodes"
try_command_on_node all $CTDB setvar AllowClientDBAttach 1

echo "Check failure detaching single test database $testdb1"
try_command_on_node 1 "! $CTDB detach $testdb1"
check_db "$testdb1"

echo
echo "Setting AllowClientDBAttach=0 on node 0"
try_command_on_node 0 $CTDB setvar AllowClientDBAttach 0

echo "Check failure detaching single test database $testdb1"
try_command_on_node 1 "! $CTDB detach $testdb1"
check_db "$testdb1"

echo
echo "Setting AllowClientDBAttach=0 on all nodes"
try_command_on_node all $CTDB setvar AllowClientDBAttach 0

echo "Check detaching single test database $testdb1"
try_command_on_node 1 "$CTDB detach $testdb1"
check_no_db "$testdb1"

######################################################################

echo
echo "Detach multiple test databases"
echo "    $testdb2, $testdb3, $testdb4"
try_command_on_node 0 $CTDB detach $testdb2 $testdb3 $testdb4

for db in "$testdb2" "$testdb3" "$testdb4" ; do
    check_no_db "$db"
done

######################################################################

echo
echo "Attach a single test database"
try_command_on_node all $CTDB setvar AllowClientDBAttach 1
try_command_on_node 0 $CTDB attach $testdb1
check_db "$testdb1"

echo
echo "Write a key to database"
try_command_on_node 0 $CTDB writekey $testdb1 foo bar
try_command_on_node 0 $CTDB catdb $testdb1
num_keys=$(sed -n -e 's/Dumped \([0-9]*\) records/\1/p' "$outfile") || true
if [ -n "$num_keys" -a $num_keys -eq 1 ]; then
    echo "GOOD: Key added to database"
else
    echo "BAD: Key did not get added to database"
    cat "$outfile"
    exit 1
fi

echo
echo "Detach test database"
try_command_on_node all $CTDB setvar AllowClientDBAttach 0
try_command_on_node 0 $CTDB detach $testdb1
check_no_db "$testdb1"

echo
echo "Re-attach test database"
try_command_on_node all $CTDB setvar AllowClientDBAttach 1
try_command_on_node 0 $CTDB attach $testdb1
check_db "$testdb1"

echo
echo "Check if the database is empty"
try_command_on_node 0 $CTDB catdb $testdb1
num_keys=$(sed -n -e 's/Dumped \([0-9]*\) records/\1/p' "$outfile") || true
if [ -n "$num_keys" -a $num_keys -eq 0 ]; then
    echo "GOOD: Database $testdb1 is empty"
else
    echo "BAD: Database $testdb1 is not empty"
    cat "$outfile"
    exit 1
fi
