#!/bin/bash

test_info()
{
    cat <<EOF
Ensure recovery doesn't resurrect deleted records from recently inactive nodes
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init

set -e

cluster_is_healthy

testdb="rec_test.tdb"

echo "Getting list of nodes..."
try_command_on_node -v any "onnode -pq all ctdb pnn | grep '^[0-9][0-9]*$'"

first=$(sed -n -e '1p' "$outfile")
second=$(sed -n -e '2p' "$outfile")
notfirst=$(tail -n +2 "$outfile")

echo "Create/wipe test database ${testdb}"
try_command_on_node $first $CTDB attach "$testdb"
try_command_on_node $first $CTDB wipedb "$testdb"

echo "store key(test1) data(value1)"
try_command_on_node $first $CTDB writekey "$testdb" test1 value1

echo "Migrate key(test1) to all nodes"
try_command_on_node all $CTDB readkey "$testdb" test1

echo "Stop node ${first}"
try_command_on_node $first $CTDB stop
wait_until_node_has_status $first stopped

echo "Delete key(test1)"
try_command_on_node $second $CTDB deletekey "$testdb" test1

database_has_zero_records ()
{
	local n
	for n in $notfirst ; do
		try_command_on_node $n $CTDB cattdb "$testdb"
		if grep -q '^key(' "$outfile" ; then
			return 1
		fi
	done

	return 0
}

echo "Get vacuum interval"
try_command_on_node -v $second $CTDB getvar VacuumInterval
vacuum_interval="${out#* = }"

echo "Wait until vacuuming deletes the record on active nodes"
# Why 4?  Steps are:
# 1. Original node processes delete queue, asks lmaster to fetch
# 2. lmaster recoverd fetches
# 3. lmaster processes delete queue
# If vacuuming is just missed then need an extra interval
t=$((vacuum_interval * 4))
wait_until "${t}/10" database_has_zero_records

echo "Continue node ${first}"
try_command_on_node $first $CTDB continue
wait_until_node_has_status $first notstopped

echo "Get database contents"
try_command_on_node -v $first $CTDB catdb "$testdb"

if grep -q '^key(' "$outfile" ; then
	echo "BAD: Deleted record has been resurrected"
	exit 1
fi

echo "GOOD: Deleted record is still gone"
