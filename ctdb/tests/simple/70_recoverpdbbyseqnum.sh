#!/bin/bash

test_info()
{
    cat <<EOF
The persistent databases are recovered using sequence number.
The recovery is performed by picking the copy of the database from the
node that has the highest sequence number and ignore the content on all
other nodes.


Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. create a persistent test database
3. test that no seqnum record blends the database during recovery
4. test that seqnum record does not blend the database during recovery

Expected results:

* that 3,4 will recover the highest seqnum database

EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init

set -e

cluster_is_healthy

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
