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

echo

check_db_num_records ()
{
	local node="$1"
	local db="$2"
	local n="$3"

	echo "Checking on node ${node} to ensure ${db} has ${n} records..."
	try_command_on_node "$node" "${CTDB} catdb ${db}"

	num=$(sed -n -e 's|^Dumped \(.*\) records$|\1|p' "$outfile")
	if [ "$num" = "$n" ] ; then
		echo "OK: Number of records=${num}"
		echo
	else
		echo "BAD: There were ${num} (!= ${n}) records"
		cat "$outfile"
		exit 1
	fi
}

check_db_num_records 0 "$TESTDB" 1
check_db_num_records 1 "$TESTDB" 1

cat <<EOF

Again, this time with 10 records, rewriting 5 of them on the 2nd node

EOF

echo "wipe test database $TESTDB"
try_command_on_node 0 $CTDB wipedb "$TESTDB"

for i in $(seq 0 9) ; do
	k="foo${i}"
	v="bar${i}@0"
	echo "write ${k}=${v} on node 0"
	try_command_on_node 0 "${CTDB} writekey ${TESTDB} ${k} ${v}"
done

for i in $(seq 1 5) ; do
	k="foo${i}"
	v="bar${i}@1"
	echo "write ${k}=${v} on node 1"
	try_command_on_node 1 "${CTDB} writekey ${TESTDB} ${k} ${v}"
done

check_db_num_records 0 "$TESTDB" 10
check_db_num_records 1 "$TESTDB" 10

cat <<EOF

Again, this time with lmaster role off on node 1

EOF

echo "wipe test database $TESTDB"
try_command_on_node 0 $CTDB wipedb "$TESTDB"

echo "switching off lmaster role on node 1"
try_command_on_node 1 $CTDB setlmasterrole off

try_command_on_node -v 1 $CTDB getcapabilities

wait_until_node_has_status 1 notlmaster 10 0

echo "write foo=bar0 on node 0"
try_command_on_node 0 $CTDB writekey "$TESTDB" "foo" "bar0"

echo "write foo=bar1 on node 1"
try_command_on_node 1 $CTDB writekey "$TESTDB" "foo" "bar1"

echo

check_db_num_records 0 "$TESTDB" 1
check_db_num_records 1 "$TESTDB" 1

if grep -q "^data(4) = \"bar1\"\$" "$outfile" ; then
	echo "OK: Data from node 1 was returned"
else
	echo "BAD: Data from node 1 was not returned"
	exit 1
fi
