#!/bin/bash

test_info()
{
    cat <<EOF
This test confirms that the deleted records are not resurrected after recovery.

Steps:

1. Create a persistent database
2. Add a record and update it few times.
3. Delete the record
4. Turn off one of the nodes
5. Add a record with same key.
6. Turn on the stopped node

Expected results:

* Check that the deleted record is present after recovery.

EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init

set -e

cluster_is_healthy

do_test()
{
# Wipe Test database
echo "wipe test database"
try_command_on_node 0 $CTDB wipedb $TESTDB

# Add a record   key=test1 data=value1
# and update values
for value in value1 value2 value3 value4 value5 ; do
	echo "store key(test1) data($value)"
	echo "\"test1\" \"$value\"" | try_command_on_node -i 0 $CTDB ptrans "$TESTDB"
done

# Delete record
echo "delete key(test1)"
try_command_on_node 0 $CTDB pdelete $TESTDB test1

# Stop a node
echo "stop node 1"
try_command_on_node 1 $CTDB stop

wait_until_node_has_status 1 stopped

# Add a record   key=test1 data=value2
echo "store key(test1) data(newvalue1)"
echo '"test1" "newvalue1"' | try_command_on_node -i 0 $CTDB ptrans "$TESTDB"

# Continue node
echo "contine node 1"
try_command_on_node 1 $CTDB continue

wait_until_node_has_status 1 notstopped

}

#
# Main test
#
TESTDB="persistent_test.tdb"

status=0

# Create a temporary persistent database to test with
echo "create persistent test database $TESTDB"
try_command_on_node 0 $CTDB attach $TESTDB persistent

do_test
if try_command_on_node 0 $CTDB pfetch $TESTDB test1 ; then
	echo "GOOD: Record was not deleted (recovery by sequence number worked)"
else
	echo "BAD: Record was deleted"
	status=1
fi

exit $status
