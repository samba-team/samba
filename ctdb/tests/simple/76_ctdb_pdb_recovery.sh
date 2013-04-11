#!/bin/bash

test_info()
{
    cat <<EOF
The recovery process based on RSN for persistent databases is defective.
For persistent databases sequence number based recovery method should be
used. This test checks for the defect in the RSN based recovery method
for persistent databases and confirms that the same issue is not observed
when using sequence number based recovery method.

Steps:

1. Create a persistent database
2. Add a record and update it few times. Set the sequence number to 5
3. Delete the record
4. Turn off one of the nodes
5. Add a record with same key. Set the sequence number to 10
6. Turn on the stopped node

Expected results:

* Check that the record is deleted (RSN based recovery) and record is
  present (sequence number based recovery)

EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init "$@"

set -e

cluster_is_healthy

# Reset configuration
ctdb_restart_when_done

do_test()
{
# Wipe Test database
echo "wipe test database"
try_command_on_node -q 0 $CTDB_TEST_WRAPPER ctdb wipedb $TESTDB

# Add a record   key=test1 data=value1
# and update values
for value in value1 value2 value3 value4 value5 ; do
	echo "store key(test1) data($value)"
	try_command_on_node -q 0 "(echo -ne $value > /tmp/test_data)"
	try_command_on_node -q 0 $CTDB_TEST_WRAPPER ctdb pstore $TESTDB test1 /tmp/test_data
done

# Update sequence number on all the nodes
echo "set __db_sequence_number__ to 5"
try_command_on_node -q 0 $CTDB_TEST_WRAPPER ctdb setdbseqnum $TESTDB 5

# Delete record
echo "delete key(test1)"
try_command_on_node -q 0 $CTDB_TEST_WRAPPER ctdb pdelete $TESTDB test1

# Stop a node
echo "stop node 1"
try_command_on_node -q 1 $CTDB_TEST_WRAPPER ctdb stop

wait_until_node_has_status 1 stopped

# Add a record   key=test1 data=value2
echo "store key(test1) data(newvalue1)"
try_command_on_node -q 0 "(echo -ne newvalue1 > /tmp/test_data)"
try_command_on_node -q 0 $CTDB_TEST_WRAPPER ctdb pstore $TESTDB test1 /tmp/test_data

echo "set __db_sequence_number__ to 6"
try_command_on_node -q 0 $CTDB_TEST_WRAPPER ctdb setdbseqnum $TESTDB 6

# Continue node
echo "contine node 1"
try_command_on_node -q 1 $CTDB_TEST_WRAPPER ctdb continue

wait_until_node_has_status 1 notstopped

}

#
# Main test
#
TESTDB="persistent_test.tdb"

status=0

# Create a temporary persistent database to test with
echo "create persistent test database $TESTDB"
try_command_on_node -q 0 $CTDB_TEST_WRAPPER ctdb attach $TESTDB persistent

# Set RecoverPDBBySeqNum = 0
echo "set RecoverPDBBySeqNum to 0"
try_command_on_node -q all $CTDB_TEST_WRAPPER ctdb setvar RecoverPDBBySeqNum 0

do_test
if try_command_on_node 0 $CTDB_TEST_WRAPPER ctdb pfetch $TESTDB test1 ; then
	echo "GOOD: Record was not deleted (recovery by RSN worked)"
else
	echo "BAD: Record was not deleted"
	status=1
fi

# Set RecoverPDBBySeqNum = 1
echo "set RecoverPDBBySeqNum to 1"
try_command_on_node -q all $CTDB_TEST_WRAPPER ctdb setvar RecoverPDBBySeqNum 1

do_test
if try_command_on_node 0 $CTDB_TEST_WRAPPER ctdb pfetch $TESTDB test1 ; then
	echo "GOOD: Record was not deleted (recovery by sequnce number worked)"
else
	echo "BAD: Record was deleted"
	status=1
fi

exit $status
