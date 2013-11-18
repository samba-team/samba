#!/bin/bash

test_info()
{
    cat <<EOF
The tunable RecoverPDBBySeqNum controls how we perform recovery
on persistent databases.
The default is that persistent databases are recovered exactly the same
way as normal databases. That is that we recover record by record.

If RecoverPDBBySeqNum is set to 1 AND if a record with the key
"__db_sequence_number__" can be found in the database, then instead we will
perform the recovery by picking the copy of the database from the node
that has the highest sequence number and ignore the content on all other
nodes.


Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. create a persistent test database
3. test that RecoveryPDBBySeqNum==0 and no seqnum record blends the database
   during recovery
4. test that RecoveryPDBBySeqNum==0 and seqnum record blends the database
   during recovery
5. test that RecoveryPDBBySeqNum==1 and no seqnum record blends the database
   during recovery
6. test that RecoveryPDBBySeqNum==1 and seqnum record does not blend the database
   during recovery

Expected results:

* that 3,4,5 will blend the databases and that 6 will recovery the highest seqnum
  database

EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init "$@"

set -e

cluster_is_healthy

# Reset configuration
ctdb_restart_when_done

try_command_on_node 0 "$CTDB listnodes"
num_nodes=$(echo "$out" | wc -l)

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


echo "Setting RecoverPDBBySeqNum=0"
try_command_on_node all $CTDB setvar "RecoverPDBBySeqNum" 0

# 3.
# If RecoverPDBBySeqNum==0  and no __db_sequence_number__
# recover record by record
#
# wipe database
echo
echo "Test that RecoverPDBBySeqNum=0 and no __db_sequence_number__ blends the database during recovery"

echo "Wipe test database"
try_command_on_node 0 $CTDB wipedb "$test_db"

add_record_per_node

# force a recovery
echo "Force a recovery"
try_command_on_node 0 $CTDB recover

# check that we now have both records on node 0
num_records=$(db_ctdb_cattdb_count_records 0 "$test_db")
if [ $num_records = "$num_nodes" ] ; then
    echo "OK: databases were blended"
else
    echo "BAD: we did not end up with the expected $num_nodes records after the recovery"
    exit 1
fi

# 4.
# If RecoverPDBBySeqNum==0  and __db_sequence_number__
# recover record by record
#
# wipe database
echo
echo "Test that RecoverPDBBySeqNum=0 and __db_sequence_number__ blends the database during recovery"

echo "Wipe the test database"
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
echo "Force a recovery"
try_command_on_node 0 $CTDB recover

# check that we now have both records on node 0
num_records=$(db_ctdb_cattdb_count_records 0 "$test_db")
if [ $num_records = "$num_nodes" ] ; then
    echo "OK: databases were blended"
else
    echo "BAD: we did not end up with the expected $num_nodes records after the recovery"
    try_command_on_node -v 0 $CTDB cattdb "$test_db"
    exit 1
fi


# set RecoverPDBBySeqNum=1
echo
echo "Setting RecoverPDBBySeqNum to 1"
try_command_on_node all $CTDB setvar "RecoverPDBBySeqNum" 1


# 5,
# If RecoverPDBBySeqNum==1  and no __db_sequence_number__
# recover whole database
#
# wipe database
echo
echo "Test that RecoverPDBBySeqNum=1 and no __db_sequence_number__ does not blend the database during recovery"
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



# 6,
# If RecoverPDBBySeqNum==1  and __db_sequence_number__
# recover whole database
#
# wipe database
echo
echo test that RecoverPDBBySeqNum==1 and __db_sequence_number__ does not blend the database during recovery
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
