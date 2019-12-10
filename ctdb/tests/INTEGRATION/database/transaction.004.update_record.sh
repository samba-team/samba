#!/usr/bin/env bash

# Verify that "ctdb update_record_persistent" creates new records and
# updates existing records in a persistent database
#
# 1. Create and wipe a persistent test database
# 2. Do a recovery
# 3. Confirm that the database is empty
# 4. Create a new record using "ctdb update_record_persistent"
# 5. Confirm the record exists in the database using "ctdb cattdb"
# 6. Update the record's value using "ctdb update_record_persistent"
# 7. Confirm that the original value no longer exists using "ctdb cattdb"

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_init

try_command_on_node 0 "$CTDB listnodes | wc -l"
num_nodes="$out"

test_db="persistent_test.tdb"

# create a temporary persistent database to test with
echo "Create persistent test database \"$test_db\""
try_command_on_node 0 $CTDB attach "$test_db" persistent


# 3.
echo "Wipe the persistent test database"
try_command_on_node 0 $CTDB wipedb "$test_db"
echo "Force a recovery"
try_command_on_node 0 $CTDB recover

# check that the database is wiped
num_records=$(db_ctdb_cattdb_count_records 1 "$test_db")
if [ $num_records = "0" ] ; then
    echo "OK: database was wiped"
else
    echo "BAD: we did not end up with an empty database"
    exit 1
fi

# 4.
echo "Create a new record in the persistent database using UPDATE_RECORD"
try_command_on_node 0 $CTDB_TEST_WRAPPER $VALGRIND update_record_persistent \
	-D "$test_db" -k "Update_Record_Persistent" -v "FirstValue"

try_command_on_node 0 "$CTDB cattdb "$test_db" | grep 'FirstValue' | wc -l"
if [ "$out" = 1 ] ; then
    echo "GOOD: we did not find the record after the create/update"
else
    echo "BAD: we did find the record after the create/update"
    exit 1
fi

# 5.
echo Modify an existing record in the persistent database using UPDATE_RECORD
try_command_on_node 0 $CTDB_TEST_WRAPPER $VALGRIND update_record_persistent \
	-D "$test_db" -k "Update_Record_Persistent" -v "SecondValue"

try_command_on_node 0 "$CTDB cattdb "$test_db" | grep 'FirstValue' | wc -l"
if [ "$out" = 0 ] ; then
    echo "GOOD: did not find old record after the modify/update"
else
    echo "BAD: we still found the old record after the modify/update"
    exit 1
fi

try_command_on_node 0 "$CTDB cattdb "$test_db" | grep 'SecondValue' | wc -l"
if [ "$out" = 1 ] ; then
    echo "GOOD: found the record after the modify/update"
else
    echo "BAD: could not find the record after the modify/update"
    exit 1
fi

echo "Wipe the persistent test databases and clean up"
try_command_on_node 0 $CTDB wipedb "$test_db"
