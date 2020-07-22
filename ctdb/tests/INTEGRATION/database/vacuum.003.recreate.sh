#!/bin/bash

# Ensure that vacuuming does not delete a record that is recreated
# before vacuuming completes.  This needs at least 3 nodes.

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_init

db="vacuum_test.tdb"

echo "Stall vacuuming on all nodes"
ctdb_onnode -p all "setvar VacuumInterval 99999"

echo
echo "Getting list of nodes..."
ctdb_get_all_pnns

# all_pnns is set above by ctdb_get_all_pnns()
# shellcheck disable=SC2154
first=$(echo "$all_pnns" | sed -n -e '1p')

echo
echo "Create/wipe test database ${db}"
ctdb_onnode "$first" "attach ${db}"
ctdb_onnode "$first" "wipedb ${db}"

echo
echo "Create a record in ${db}"
ctdb_onnode "$first" "writekey ${db} key value1"

echo
echo "Migrate record to all nodes"
ctdb_onnode all "readkey ${db} key"

echo
echo "Confirm that all nodes have the record"
check_cattdb_num_records "$db" 1 "$all_pnns"

echo
echo "Determine lmaster node for key"
testprog_onnode "$first" "ctdb-db-test get-lmaster key"
# $out is set above by testprog_onnode()
# shellcheck disable=SC2154
lmaster="$out"
echo "lmaster=${lmaster}"

non_lmaster=""
# Find a non-lmaster node
for i in $all_pnns ; do
	if [ "$i" != "$lmaster" ] ; then
		non_lmaster="$i"
		break
	fi
done
if [ -z "$non_lmaster" ] ; then
	ctdb_test_fail "Could not find non-lmaster node for key"
fi

another_non_lmaster=""
# Find another non-lmaster node
for i in $all_pnns ; do
	if [ "$i" != "$lmaster" ] && [ "$i" != "$non_lmaster" ] ; then
		another_non_lmaster="$i"
		break
	fi
done
if [ -z "$another_non_lmaster" ] ; then
	ctdb_test_fail "Could not find another non-lmaster node for key"
fi

vacuum_test ()
{
	local db="$1"
	local key="$2"
	local val="$3"
	local dnode="$4"
	local rnode="$5"
	local rrun="$6"

	echo
	echo '............................................................'
	printf 'Delete key %s on node %d\n' "$key" "$dnode"
	printf 'Recreate on node %d after %d vacuuming run(s)\n' \
	       "$rnode" "$rrun"
	echo '............................................................'

	echo
	echo "Delete key \"${key}\" from node ${dnode}"
	ctdb_onnode "$dnode" "deletekey ${db} ${key}"

	if [ "$rrun" -eq 0 ] ; then
		echo "Recreate record on node ${rnode}"
		ctdb_onnode "$rnode" "writekey ${db} ${key} ${val}"
	fi

	echo "Do a fast vacuuming run on node ${dnode}"
	testprog_onnode "$dnode" "ctdb-db-test vacuum ${db}"

	if [ "$rrun" -eq 1 ] ; then
		echo "Recreate record on node ${rnode}"
		ctdb_onnode "$rnode" "writekey ${db} ${key} ${val}"
	fi

	echo "Do a fast vacuuming run on lmaster node ${lmaster}"
	testprog_onnode "$lmaster" "ctdb-db-test vacuum ${db}"

	if [ "$rrun" -eq 2 ] ; then
		echo "Recreate record on node ${rnode}"
		ctdb_onnode "$rnode" "writekey ${db} ${key} ${val}"
	fi

	echo "Do a fast vacuuming run on lmaster node ${lmaster}"
	testprog_onnode "$lmaster" "ctdb-db-test vacuum ${db}"

	echo
	echo "Confirm the record still exists on all nodes"
	check_cattdb_num_records "$db" 1 "$all_pnns"

	echo
	echo "Confirm the record contains correct value"
	db_confirm_key_has_value "$first" "$db" "$key" "$val"
}

vacuum_test "$db" "key" "value01" "$non_lmaster" "$non_lmaster" 0
vacuum_test "$db" "key" "value02" "$non_lmaster" "$another_non_lmaster" 0
vacuum_test "$db" "key" "value03" "$non_lmaster" "$lmaster" 0
vacuum_test "$db" "key" "value04" "$lmaster" "$non_lmaster" 0
vacuum_test "$db" "key" "value05" "$lmaster" "$lmaster" 0

vacuum_test "$db" "key" "value06" "$non_lmaster" "$non_lmaster" 1
vacuum_test "$db" "key" "value07" "$non_lmaster" "$lmaster" 1
vacuum_test "$db" "key" "value08" "$non_lmaster" "$another_non_lmaster" 1

vacuum_test "$db" "key" "value09" "$non_lmaster" "$non_lmaster" 2
vacuum_test "$db" "key" "value10" "$non_lmaster" "$lmaster" 2
vacuum_test "$db" "key" "value11" "$non_lmaster" "$another_non_lmaster" 2
