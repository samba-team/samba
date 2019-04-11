#!/bin/bash

test_info()
{
    cat <<EOF
Verify that the ctdb ptrans works as expected

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. Pipe some operation to ctdb ptrans and validate the TDB contents with ctdb catdb

Expected results:

* ctdb ptrans works as expected.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init

set -e

cluster_is_healthy

TESTDB="ptrans_test.tdb"

# Create a temporary persistent database to test with
echo "create persistent test database $TESTDB"
try_command_on_node 0 $CTDB attach $TESTDB persistent

# Wipe Test database
echo "wipe test database"
try_command_on_node 0 $CTDB wipedb $TESTDB

##########

echo "Adding 3 records"

items='
"key1" "value1"
"key2" "value1"
"key3" "value1"'

echo "$items" | try_command_on_node -i 0 $CTDB ptrans "$TESTDB"

try_command_on_node 0 $CTDB catdb "$TESTDB"

n=$(grep -c '^key.*= "key.*"' "$outfile" || true)

if [ $n -ne 3 ] ; then
    echo "BAD: expected 3 keys in..."
    cat "$outfile"
    exit 1
else
    echo "GOOD: 3 records were inserted"
fi

##########

echo "Deleting 1 record, updating 1, adding 1 new record, 1 bogus input line"

items='
"key1" ""
"key2" "value2"
"key3"
"key4" "value1"'

echo "$items" | try_command_on_node -i 0 $CTDB ptrans "$TESTDB"

try_command_on_node 0 $CTDB catdb "$TESTDB"

n=$(grep -c '^key.*= "key.*"' "$outfile" || true)

if [ $n -ne 3 ] ; then
    echo "BAD: expected 3 keys in..."
    cat "$outfile"
    exit 1
else
    echo "GOOD: 3 records found"
fi

##########

echo "Verifying records"

while read key value ; do
    try_command_on_node 0 $CTDB pfetch "$TESTDB" "$key"
    if [ "$value" != "$out" ] ; then
	echo "BAD: for key \"$key\" expected \"$value\" but got \"$out\""
	exit 1
    else
	echo "GOOD: for key \"$key\" got \"$out\""
    fi
done <<EOF
key2 value2
key3 value1
key4 value1
EOF

##########

echo "Deleting all records"

items='
"key2" ""
"key3" ""
"key4" ""'

echo "$items" | try_command_on_node -i 0 $CTDB ptrans "$TESTDB"

try_command_on_node 0 $CTDB catdb "$TESTDB"

n=$(grep -c '^key.*= "key.*"' "$outfile" || true)

if [ $n -ne 0 ] ; then
    echo "BAD: expected 0 keys in..."
    cat "$outfile"
    exit 1
else
    echo "GOOD: 0 records found"
fi
