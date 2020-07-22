#!/bin/bash

test_info()
{
    cat <<EOF
Test CTDB cluster wide traverse code.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Create a test database
2. Add records on different nodes
3. Run traverse

Expected results:

* All records are retrieved.

EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init

set -e

cluster_is_healthy

try_command_on_node 0 "$CTDB listnodes"
num_nodes=$(echo "$out" | wc -l)

num_records=1000

TESTDB="traverse_test.tdb"

echo "create test database $TESTDB"
try_command_on_node 0 $CTDB attach $TESTDB

echo "wipe test database $TESTDB"
try_command_on_node 0 $CTDB wipedb $TESTDB

echo "Add $num_records records to database"
i=0
while [ $i -lt $num_records ]; do
	key=$(printf "key-%04x" $i)
	value="value-$i"

	n=$[ $i % $num_nodes ]
	try_command_on_node $n $CTDB writekey $TESTDB $key $value

	i=$[ $i + 1 ]
done

echo "Start a traverse and collect records"
try_command_on_node 0 $CTDB catdb $TESTDB

num_read=$(tail -n 1 "$outfile" | cut -d\  -f2)
if [ $num_read -eq $num_records ]; then
	echo "GOOD: All $num_records records retrieved"
	status=0
else
	echo "BAD: Only $num_read/$num_records records retrieved"
	status=1
fi

exit $status
