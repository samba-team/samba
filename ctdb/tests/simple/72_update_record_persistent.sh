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

# create a temporary persistent database to test with
echo create persistent test database persistent_test.tdb
try_command_on_node -q 0 $CTDB_TEST_WRAPPER ctdb attach persistent_test.tdb persistent


# 3,
echo wipe the persistent test database
try_command_on_node -q 0 $CTDB_TEST_WRAPPER ctdb wipedb persistent_test.tdb
echo force a recovery
try_command_on_node -q 0 $CTDB_TEST_WRAPPER ctdb recover

# check that the database is wiped
num_records=$(try_command_on_node -v -pq 1 $CTDB_TEST_WRAPPER ctdb cattdb persistent_test.tdb | grep key | wc -l)
[ $num_records != "0" ] && {
    echo "BAD: we did not end up with an empty database"
    exit 1
}
echo "OK. database was wiped"

TDB=`try_command_on_node -v -q 0 $CTDB_TEST_WRAPPER ctdb getdbmap | grep persistent_test.tdb | sed -e "s/.*path://" -e "s/ .*//"`

# 4,
echo Create a new record in the persistent database using UPDATE_RECORD
try_command_on_node -q 0 $CTDB_TEST_WRAPPER ctdb_update_record_persistent  --database=persistent_test.tdb --record=Update_Record_Persistent --value=FirstValue

num_records=`tdbdump $TDB | grep "FirstValue" | wc -l`
[ $num_records != 1 ] && {
    echo "BAD: we did find the record after the create/update"
    exit 1
}

# 5,
echo Modify an existing record in the persistent database using UPDATE_RECORD
try_command_on_node -q 0 $CTDB_TEST_WRAPPER ctdb_update_record_persistent  --database=persistent_test.tdb --record=Update_Record_Persistent --value=SecondValue

num_records=`tdbdump $TDB | grep "FirstValue" | wc -l`
[ $num_records != 0 ] && {
    echo "BAD: we still found the old record after the modify/update"
    exit 1
}

num_records=`tdbdump $TDB | grep "SecondValue" | wc -l`
[ $num_records != 1 ] && {
    echo "BAD: could not find the record after the modify/update"
    exit 1
}


echo wipe the persistent test databases and clean up
try_command_on_node -q 0 $CTDB_TEST_WRAPPER ctdb wipedb persistent_test.tdb
