#!/bin/bash

test_info()
{
    cat <<EOF
Confirm that traverses of volatile databases work as expected

This is a very simple example.  It writes a single record, updates it
on another node and then confirms that the correct value is found when
traversing.  It then repeats this after removing the LMASTER role from
the node where the value is updated.

Expected results:

* The expected records should be found

EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init

set -e

cluster_is_healthy

#
# Main test
#
TESTDB="traverse_db.tdb"

echo "create volatile test database $TESTDB"
try_command_on_node 0 $CTDB attach "$TESTDB"

echo "wipe test database $TESTDB"
try_command_on_node 0 $CTDB wipedb "$TESTDB"

echo "write foo=bar0 on node 0"
try_command_on_node 0 $CTDB writekey "$TESTDB" "foo" "bar0"

echo "write foo=bar1 on node 1"
try_command_on_node 1 $CTDB writekey "$TESTDB" "foo" "bar1"

echo "do traverse on node 0"
try_command_on_node -v 0 $CTDB catdb "$TESTDB"

echo "do traverse on node 1"
try_command_on_node -v 1 $CTDB catdb "$TESTDB"

cat <<EOF

Again, this time with lmaster role off on node 1

EOF

echo "wipe test database $TESTDB"
try_command_on_node 0 $CTDB wipedb "$TESTDB"

echo "switching off lmaster role on node 1"
try_command_on_node 1 $CTDB setlmasterrole off

try_command_on_node -v 1 $CTDB getcapabilities

wait_until_node_has_status 1 notlmaster 10 0
# Wait for recovery and new VNN map to be pushed
#sleep_for 10

echo "write foo=bar0 on node 0"
try_command_on_node 0 $CTDB writekey "$TESTDB" "foo" "bar0"

echo "write foo=bar1 on node 1"
try_command_on_node 1 $CTDB writekey "$TESTDB" "foo" "bar1"

echo "do traverse on node 0"
try_command_on_node -v 0 $CTDB catdb "$TESTDB"

num=$(sed -n -e 's|^Dumped \(.*\) records$|\1|p' "$outfile")
if [ "$num" = 1 ] ; then
	echo "OK: There was 1 record"
else
	echo "BAD: There were ${num} (!= 1) records"
	exit 1
fi

if grep -q "^data(4) = \"bar1\"\$" "$outfile" ; then
	echo "OK: Data from node 1 was returned"
else
	echo "BAD: Data from node 1 was not returned"
	exit 1
fi
