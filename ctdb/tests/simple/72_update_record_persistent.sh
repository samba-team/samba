#!/bin/bash

test_info()
{
    cat <<EOF
UPDATE_RECORD control should be able to create new records and update
existing records in a persistent database.

Prerequisites:

* An active CTDB cluster with at least one active node.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. create a persistent test database
3, wipe the database to make sure it is empty
4, create a new record
5, update the record

Expected results:

* 4 created record found in the tdb
* 5 updated record found in the tdb

EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init "$@"

set -e

cluster_is_healthy

try_command_on_node 0 "$CTDB listnodes"
num_nodes=$(echo "$out" | wc -l)

test_db="persistent_test.tdb"

# create a temporary persistent database to test with
echo "Create persistent test database \"$test_db\""
try_command_on_node 0 $CTDB attach "$test_db" persistent


# 3,
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

# 4,
echo "Create a new record in the persistent database using UPDATE_RECORD"
try_command_on_node 0 $CTDB_TEST_WRAPPER ctdb_update_record_persistent  --database="$test_db" --record=Update_Record_Persistent --value=FirstValue

try_command_on_node 0 "$CTDB cattdb "$test_db" | grep 'FirstValue' | wc -l"
if [ "$out" = 1 ] ; then
    echo "GOOD: we did not find the record after the create/update"
else
    echo "BAD: we did find the record after the create/update"
    exit 1
fi

# 5,
echo Modify an existing record in the persistent database using UPDATE_RECORD
try_command_on_node 0 $CTDB_TEST_WRAPPER ctdb_update_record_persistent  --database="$test_db" --record=Update_Record_Persistent --value=SecondValue

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
