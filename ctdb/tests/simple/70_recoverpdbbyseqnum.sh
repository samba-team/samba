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

try_command_on_node 0 "$CTDB listnodes"
num_nodes=$(echo "$out" | wc -l)

# create a temporary persistent database to test with
echo create persistent test database persistent_test.tdb
try_command_on_node 0 $CTDB_TEST_WRAPPER ctdb attach persistent_test.tdb persistent


# set RecoverPDBBySeqNum=0
echo "setting RecoverPDBBySeqNum to 0"
try_command_on_node all $CTDB_TEST_WRAPPER ctdb setvar RecoverPDBBySeqNum 0



# 3,
# If RecoverPDBBySeqNum==0  and no __db_sequence_number__
# recover record by record
#
# wipe database
echo
echo test that RecoverPDBBySeqNum==0 and no __db_sequence_number__ blends the database during recovery
echo wipe the test database
try_command_on_node 0 $CTDB_TEST_WRAPPER ctdb wipedb persistent_test.tdb

# add one record to node 0   key==ABC  data==ABC
TDB=`try_command_on_node -v 0 $CTDB_TEST_WRAPPER ctdb getdbmap | grep persistent_test.tdb | sed -e "s/.*path://" -e "s/ .*//"`
echo "store key(ABC) data(ABC) on node 0"
try_command_on_node 0 $CTDB_TEST_WRAPPER ctdb tstore $TDB 0x414243 0x070000000000000000000000000000000000000000000000414243
#
# add one record to node 1   key==DEF  data==DEF
TDB=`try_command_on_node -v 1 $CTDB_TEST_WRAPPER ctdb getdbmap | grep persistent_test.tdb | sed -e "s/.*path://" -e "s/ .*//"`
echo "store key(DEF) data(DEF) on node 1"
try_command_on_node 1 $CTDB_TEST_WRAPPER ctdb tstore $TDB 0x444546 0x070000000000000000000000000000000000000000000000444546

# force a recovery
echo force a recovery
try_command_on_node 0 $CTDB_TEST_WRAPPER ctdb recover

# check that we now have both records on node 0
num_records=$(try_command_on_node -v -pq 0 $CTDB_TEST_WRAPPER ctdb cattdb persistent_test.tdb | grep key | egrep "ABC|DEF" | wc -l)
[ $num_records != "2" ] && {
    echo "BAD: we did not end up with the expected two records after the recovery"
    exit 1
}
echo "OK. databases were blended"



# 4,
# If RecoverPDBBySeqNum==0  and __db_sequence_number__
# recover record by record
#
# wipe database
echo
echo test that RecoverPDBBySeqNum==0 and __db_sequence_number__ blends the database during recovery
echo wipe the test database
try_command_on_node 0 $CTDB_TEST_WRAPPER ctdb wipedb persistent_test.tdb

echo "add __db_sequence_number__==5 record to all nodes"
try_command_on_node -v 0 $CTDB_TEST_WRAPPER ctdb nodestatus all | grep pnn | sed -e"s/^pnn://" -e "s/ .*//" | while read PNN; do
    TDB=`try_command_on_node -v $PNN $CTDB_TEST_WRAPPER ctdb getdbmap | grep persistent_test.tdb | sed -e "s/.*path://" -e "s/ .*//"`
    try_command_on_node $PNN $CTDB_TEST_WRAPPER ctdb tstore $TDB 0x5f5f64625f73657175656e63655f6e756d6265725f5f00 0x0700000000000000000000000000000000000000000000000500000000000000
done

# add one record to node 0   key==ABC  data==ABC
TDB=`try_command_on_node -v 0 $CTDB_TEST_WRAPPER ctdb getdbmap | grep persistent_test.tdb | sed -e "s/.*path://" -e "s/ .*//"`
echo "store key(ABC) data(ABC) on node 0"
try_command_on_node 0 $CTDB_TEST_WRAPPER ctdb tstore $TDB 0x414243 0x070000000000000000000000000000000000000000000000414243
echo "add __db_sequence_number__==7 record to node 0"
try_command_on_node 0 $CTDB_TEST_WRAPPER ctdb tstore $TDB 0x5f5f64625f73657175656e63655f6e756d6265725f5f00 0x0700000000000000000000000000000000000000000000000700000000000000

# add one record to node 1   key==DEF  data==DEF
TDB=`try_command_on_node -v 1 $CTDB_TEST_WRAPPER ctdb getdbmap | grep persistent_test.tdb | sed -e "s/.*path://" -e "s/ .*//"`
echo "store key(DEF) data(DEF) on node 1"
try_command_on_node 1 $CTDB_TEST_WRAPPER ctdb tstore $TDB 0x444546 0x070000000000000000000000000000000000000000000000444546
echo "add __db_sequence_number__==8 record to node 1"
try_command_on_node 1 $CTDB_TEST_WRAPPER ctdb tstore $TDB 0x5f5f64625f73657175656e63655f6e756d6265725f5f00 0x0700000000000000000000000000000000000000000000000800000000000000

# force a recovery
echo force a recovery
try_command_on_node 0 $CTDB_TEST_WRAPPER ctdb recover

# check that we now have both records on node 0
num_records=$(try_command_on_node -v -pq 0 $CTDB_TEST_WRAPPER ctdb cattdb persistent_test.tdb | grep key | egrep "ABC|DEF" | wc -l)
[ $num_records != "2" ] && {
    echo "BAD: we did not end up with the expected two records after the recovery"
    exit 1
}
echo "OK. databases were blended"



# set RecoverPDBBySeqNum=1
echo
echo "setting RecoverPDBBySeqNum to 1"
try_command_on_node all $CTDB_TEST_WRAPPER ctdb setvar RecoverPDBBySeqNum 1



# 5,
# If RecoverPDBBySeqNum==1  and no __db_sequence_number__
# recover record by record
#
# wipe database
echo
echo test that RecoverPDBBySeqNum==1 and no __db_sequence_number__ blends the database during recovery
echo wipe the test database
try_command_on_node 0 $CTDB_TEST_WRAPPER ctdb wipedb persistent_test.tdb

# add one record to node 0   key==ABC  data==ABC
TDB=`try_command_on_node -v 0 $CTDB_TEST_WRAPPER ctdb getdbmap | grep persistent_test.tdb | sed -e "s/.*path://" -e "s/ .*//"`
echo "store key(ABC) data(ABC) on node 0"
try_command_on_node 0 $CTDB_TEST_WRAPPER ctdb tstore $TDB 0x414243 0x070000000000000000000000000000000000000000000000414243

# add one record to node 1   key==DEF  data==DEF
TDB=`try_command_on_node -v 1 $CTDB_TEST_WRAPPER ctdb getdbmap | grep persistent_test.tdb | sed -e "s/.*path://" -e "s/ .*//"`
echo "store key(DEF) data(DEF) on node 1"
try_command_on_node 1 $CTDB_TEST_WRAPPER ctdb tstore $TDB 0x444546 0x070000000000000000000000000000000000000000000000444546

# force a recovery
echo force a recovery
try_command_on_node 0 $CTDB_TEST_WRAPPER ctdb recover

# check that we now have both records on node 0
num_records=$(try_command_on_node -v -pq 0 $CTDB_TEST_WRAPPER ctdb cattdb persistent_test.tdb | grep key | egrep "ABC|DEF" | wc -l)
[ $num_records != "2" ] && {
    echo "BAD: we did not end up with the expected two records after the recovery"
    exit 1
}
echo "OK. databases were blended"



# 6,
# If RecoverPDBBySeqNum==1  and __db_sequence_number__
# recover whole database
#
# wipe database
echo
echo test that RecoverPDBBySeqNum==1 and __db_sequence_number__ does not blend the database during recovery
echo wipe the test database
try_command_on_node 0 $CTDB_TEST_WRAPPER ctdb wipedb persistent_test.tdb

echo "add __db_sequence_number__==5 record to all nodes"
try_command_on_node -v 0 $CTDB_TEST_WRAPPER ctdb nodestatus all | grep pnn | sed -e"s/^pnn://" -e "s/ .*//" | while read PNN; do
    TDB=`try_command_on_node -v $PNN $CTDB_TEST_WRAPPER ctdb getdbmap | grep persistent_test.tdb | sed -e "s/.*path://" -e "s/ .*//"`
    try_command_on_node $PNN $CTDB_TEST_WRAPPER ctdb tstore $TDB 0x5f5f64625f73657175656e63655f6e756d6265725f5f00 0x0700000000000000000000000000000000000000000000000500000000000000
done


# add one record to node 0   key==ABC  data==ABC
TDB=`try_command_on_node -v 0 $CTDB_TEST_WRAPPER ctdb getdbmap | grep persistent_test.tdb | sed -e "s/.*path://" -e "s/ .*//"`
echo "store key(ABC) data(ABC) on node 0"
try_command_on_node 0 $CTDB_TEST_WRAPPER ctdb tstore $TDB 0x414243 0x070000000000000000000000000000000000000000000000414243
echo "add __db_sequence_number__==7 record to node 0"
try_command_on_node 0 $CTDB_TEST_WRAPPER ctdb tstore $TDB 0x5f5f64625f73657175656e63655f6e756d6265725f5f00 0x0700000000000000000000000000000000000000000000000700000000000000

# add one record to node 1   key==DEF  data==DEF
TDB=`try_command_on_node -v 1 $CTDB_TEST_WRAPPER ctdb getdbmap | grep persistent_test.tdb | sed -e "s/.*path://" -e "s/ .*//"`
echo "store key(DEF) data(DEF) on node 1"
try_command_on_node 1 $CTDB_TEST_WRAPPER ctdb tstore $TDB 0x444546 0x070000000000000000000000000000000000000000000000444546
echo "add __db_sequence_number__==8 record to node 1"
try_command_on_node 1 $CTDB_TEST_WRAPPER ctdb tstore $TDB 0x5f5f64625f73657175656e63655f6e756d6265725f5f00 0x0700000000000000000000000000000000000000000000000800000000000000

# force a recovery
echo force a recovery
try_command_on_node 0 $CTDB_TEST_WRAPPER ctdb recover

# check that we now have both records on node 0
num_records=$(try_command_on_node -v -pq 0 $CTDB_TEST_WRAPPER ctdb cattdb persistent_test.tdb | grep key | egrep "ABC|DEF" | wc -l)
[ $num_records != "1" ] && {
    echo "BAD: we did not end up with the expected single record after the recovery"
    exit 1
}

echo "OK. databases were not blended"



# set RecoverPDBBySeqNum=1
echo "setting RecoverPDBBySeqNum back to 0"
try_command_on_node all $CTDB_TEST_WRAPPER ctdb setvar RecoverPDBBySeqNum 0
