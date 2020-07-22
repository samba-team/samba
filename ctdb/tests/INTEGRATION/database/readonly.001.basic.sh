#!/bin/bash

test_info()
{
    cat <<EOF
Read-only records can be activated at runtime using a ctdb command.
If read-only records are not activated, then any attempt to fetch a read-only
copy should be automatically upgraded to a read-write fetch_lock().

If read-only delegations are present, then any attempt to aquire a read-write
fetch_lock will trigger all delegations to be revoked before the fetch lock
completes.


Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. create a test database and some records
3. try to fetch read-only records, this should not result in any delegations
4. activate read-only support
5. try to fetch read-only records, this should result in delegations
6. do a fetchlock  and the delegations should be revoked
7. try to fetch read-only records, this should result in delegations
8. do a recovery  and the delegations should be revoked

Expected results:

Delegations should be created and revoked as above

EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init

set -e

cluster_is_healthy

######################################################################

# Confirm that no nodes have databases with read-only delegations
check_no_readonly ()
{
    try_command_on_node all $CTDB cattdb $testdb
    local ro_flags="RO_HAVE_READONLY|RO_HAVE_DELEGATIONS"
    local numreadonly=$(grep -c -E "$ro_flags" "$outfile") || true
    if [ $numreadonly -eq 0 ] ; then
	echo "GOOD: no read-only delegations"
    else
	echo "BAD: there are read-only delegations"
	cat "$outfile"
	exit 1
    fi
}

# Check that the test record has the correct read-only flags on the
# given nodes.  The first node is the dmaster, which should know there
# are delegations but should not be flagged as having a read-only
# copy.  Subsequent nodes should have a read-only copy but not know
# about any (other) delegations.
check_readonly ()
{
    local dmaster="$1" ; shift
    local others="$*"

    local count

    try_command_on_node $dmaster $CTDB cattdb $testdb
    count=$(grep -c -E "RO_HAVE_DELEGATIONS" "$outfile") || true
    if [ $count -eq 1 ] ; then
	echo "GOOD: dmaster ${dmaster} has read-only delegations"
    else
	echo "BAD: dmaster ${dmaster} has no read-only delegations"
	cat "$outfile"
	exit 1
    fi
    count=$(grep -c -E "RO_HAVE_READONLY" "$outfile") || true
    if [ $count -ne 0 ] ; then
	echo "BAD: dmaster ${dmaster} has a read-only copy"
	cat "$outfile"
	exit 1
    fi

    local o
    for o in $others ; do
	try_command_on_node $o $CTDB cattdb $testdb
	count=$(grep -c -E "RO_HAVE_READONLY" "$outfile") || true
	if [ $count -eq 1 ] ; then
	    echo "GOOD: node ${o} has a read-only copy"
	else
	    echo "BAD: node ${o} has no read-only copy"
	    cat "$outfile"
	    exit 1
	fi
	count=$(grep -c -E "RO_HAVE_DELEGATIONS" "$outfile") || true
	if [ $count -ne 0 ] ; then
	    echo "BAD: other node ${o} has read-only delegations"
	    cat "$outfile"
	    exit 1
	fi
    done
}

######################################################################

echo "Get list of nodes..."
try_command_on_node any $CTDB -X listnodes
all_nodes=$(awk -F'|' '{print $2}' "$outfile")

######################################################################

testdb="test.tdb"
echo "Create test database \"${testdb}\""
try_command_on_node 0 $CTDB attach $testdb

echo "Create some records..."
try_command_on_node all $CTDB_TEST_WRAPPER $VALGRIND update_record \
	-D ${testdb} -k testkey

######################################################################

echo "Try some readonly fetches, these should all be upgraded to full fetchlocks..."
try_command_on_node all $CTDB_TEST_WRAPPER $VALGRIND fetch_readonly \
	-D ${testdb} -k testkey

check_no_readonly

######################################################################

echo "Activate read-only record support for \"$testdb\"..."
try_command_on_node all $CTDB setdbreadonly $testdb

# Database should be tagged as READONLY
try_command_on_node 0 $CTDB getdbmap
db_details=$(awk -v db="$testdb" '$2 == foo="name:" db { print }' "$outfile")
if grep -q "READONLY" <<<"$db_details" ; then
    echo "GOOD: read-only record support is enabled"
else
    echo "BAD: could not activate read-only support"
    echo "$db_details"
    exit 1
fi

######################################################################

echo "Create 1 read-only delegation ..."
# dmaster=1
try_command_on_node 1 $CTDB_TEST_WRAPPER $VALGRIND update_record \
	-D ${testdb} -k testkey

# Fetch read-only to node 0
try_command_on_node 0 $CTDB_TEST_WRAPPER $VALGRIND fetch_readonly \
	-D ${testdb} -k testkey

check_readonly 1 0

######################################################################

echo "Verify that a fetchlock revokes read-only delegations..."
# Node 1 becomes dmaster
try_command_on_node 1 $CTDB_TEST_WRAPPER $VALGRIND update_record \
	-D ${testdb} -k testkey

check_no_readonly

######################################################################

echo "Create more read-only delegations..."
dmaster=1
try_command_on_node $dmaster $CTDB_TEST_WRAPPER $VALGRIND update_record \
	-D ${testdb} -k testkey

others=""
for n in $all_nodes ; do
    if [ "$n" != "$dmaster" ] ; then
	# Fetch read-only copy to this node
	try_command_on_node $n $CTDB_TEST_WRAPPER $VALGRIND fetch_readonly \
		-D ${testdb} -k testkey
	others="${others} ${n}"
    fi
done

check_readonly $dmaster $others

######################################################################

echo "Verify that a recovery will revoke the delegations..."
try_command_on_node 0 $CTDB recover

check_no_readonly
