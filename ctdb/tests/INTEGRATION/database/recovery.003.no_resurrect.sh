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
ctdb_get_all_pnns

first=$(echo "$all_pnns" | sed -n -e '1p')
second=$(echo "$all_pnns" | sed -n -e '2p')
notfirst=$(echo "$all_pnns" | tail -n +2)

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
	# shellcheck disable=SC2086
	# $notfirst can be multi-word
	check_cattdb_num_records "$testdb" 0 "$notfirst"
}

echo "Trigger a recovery"
try_command_on_node "$second" $CTDB recover

echo "Checking that database has 0 records"
database_has_zero_records

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
