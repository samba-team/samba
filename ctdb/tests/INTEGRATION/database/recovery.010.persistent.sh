#!/usr/bin/env bash

# Ensure that persistent databases are correctly recovered by database
# sequence number
#
# 1. Create and wipe a persistent test database
# 2. Directly add a single record to the database on each node
# 3. Trigger a recover
# 4. Ensure that the database contains only a single record
#
# Repeat but with sequence numbers set by hand on each node

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_init

try_command_on_node 0 "$CTDB listnodes | wc -l"
num_nodes="$out"

add_record_per_node ()
{
    _i=0
    while [ $_i -lt $num_nodes ] ; do
	_k="KEY${_i}"
	_d="DATA${_i}"
	echo "Store key(${_k}) data(${_d}) on node ${_i}"
	db_ctdb_tstore $_i "$test_db" "$_k" "$_d"
	_i=$(($_i + 1))
    done
}

test_db="persistent_test.tdb"
echo "Create persistent test database \"$test_db\""
try_command_on_node 0 $CTDB attach "$test_db" persistent

# 3,
# If no __db_sequence_number__ recover whole database
#

echo
echo "Test that no __db_sequence_number__ does not blend the database during recovery"

# wipe database
echo "Wipe the test database"
try_command_on_node 0 $CTDB wipedb "$test_db"

add_record_per_node

# force a recovery
echo force a recovery
try_command_on_node 0 $CTDB recover

# Check that we now have 1 record on node 0
num_records=$(db_ctdb_cattdb_count_records 0 "$test_db")
if [ $num_records = "1" ] ; then
    echo "OK: databases were not blended"
else
    echo "BAD: we did not end up with the expected single record after the recovery"
    exit 1
fi


# 4,
# If __db_sequence_number__  recover whole database
#

echo
echo test that __db_sequence_number__ does not blend the database during recovery

# wipe database
echo wipe the test database
try_command_on_node 0 $CTDB wipedb persistent_test.tdb

add_record_per_node

echo "Add __db_sequence_number__==5 record to all nodes"
pnn=0
while [ $pnn -lt $num_nodes ] ; do
    db_ctdb_tstore_dbseqnum $pnn "$test_db" 5
    pnn=$(($pnn + 1))
done

echo "Set __db_sequence_number__ to 7 on node 0"
db_ctdb_tstore_dbseqnum 0 "$test_db" 7

echo "Set __db_sequence_number__ to 8 on node 1"
db_ctdb_tstore_dbseqnum 1 "$test_db" 8


# force a recovery
echo force a recovery
try_command_on_node 0 $CTDB recover

# check that we now have both records on node 0
num_records=$(db_ctdb_cattdb_count_records 0 "$test_db")
if [ $num_records = "1" ] ; then
    echo "OK: databases were not blended"
else
    echo "BAD: we did not end up with the expected single record after the recovery"
    exit 1
fi
