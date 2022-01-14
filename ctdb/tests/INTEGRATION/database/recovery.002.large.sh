#!/usr/bin/env bash

# Test recovery of large volatile and persistent databases

# Recovery now uses DB_PULL and DB_PUSH_START/DB_PUSH_CONFIRM
# controls.  This sends the records in batches of ~RecBufferSizeLimit
# in size at a time.  Test that large databases are re-assembled
# correctly.

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_init

#
# Main test
#
TEST1DB="large_persistent_db.tdb"
TEST2DB="large_volatile_db.tdb"
RECDATA=$(onnode 0 mktemp)

# Create a persistent database to test
echo "create persistent test database $TEST1DB"
try_command_on_node 0 $CTDB attach $TEST1DB persistent

# Wipe Test database
echo "wipe test database $TEST1DB"
try_command_on_node 0 $CTDB wipedb $TEST1DB

# Create dummy record data
echo "creating dummy record data"
onnode 0 dd if=/dev/urandom of=$RECDATA bs=10K count=1

# Add 345 records
echo "Adding 345 records"
for i in $(seq 1 345) ; do
    try_command_on_node 0 $CTDB pstore $TEST1DB record$i $RECDATA || exit 1
done

num_records=$(db_ctdb_cattdb_count_records 0 $TEST1DB)
if [ $num_records = "345" ] ; then
	echo "OK: records added correctly"
else
	echo "BAD: persistent database has $num_records of 345 records"
	try_command_on_node -v 0 "$CTDB cattdb $TEST1DB | tail -n 1"
	exit 1
fi

# Create a volatile database to test
echo "create volatile test database $TEST2DB"
try_command_on_node 0 $CTDB attach $TEST2DB

# Wipe Test database
echo "wipe test database $TEST2DB"
try_command_on_node 0 $CTDB wipedb $TEST2DB

# Create dummy record data
v1="1234567890"
v2="$v1$v1$v1$v1$v1$v1$v1$v1$v1$v1"
v3="$v2$v2$v2$v2$v2$v2$v2$v2$v2$v2"

# Add 1234 records
echo "Adding 1234 records"
for i in $(seq 1 1234) ; do
    try_command_on_node 0 $CTDB writekey $TEST2DB record$i $v3 || exit 1
done

num_records=$(db_ctdb_cattdb_count_records 0 $TEST2DB)
if [ $num_records = "1234" ] ; then
	echo "OK: records added correctly"
else
	echo "BAD: volatile database has $num_records of 1234 records"
	try_command_on_node -v 0 "$CTDB cattdb $TEST2DB | tail -n 1"
	exit 1
fi

echo
leader_get 0
# Set RecBufferSizeLimit to 10000
ctdb_onnode "$leader" setvar RecBufferSizeLimit 10000

# Do a recovery
echo "force recovery"
try_command_on_node 0 $CTDB recover

wait_until_node_has_status 0 recovered 30

# check that there are correct number of records
num_records=$(db_ctdb_cattdb_count_records 0 $TEST1DB)
if [ $num_records = "345" ] ; then
	echo "OK: persistent database recovered correctly"
else
	echo "BAD: persistent database has $num_records of 345 records"
	try_command_on_node -v 0 "$CTDB cattdb $TEST1DB | tail -n 1"
	exit 1
fi

num_records=$(db_ctdb_cattdb_count_records 0 $TEST2DB)
if [ $num_records = "1234" ] ; then
	echo "OK: volatile database recovered correctly"
else
	echo "BAD: volatile database has $num_records of 1234 records"
	try_command_on_node -v 0 "$CTDB cattdb $TEST2DB | tail -n 1"
	exit 1
fi
