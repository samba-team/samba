#!/bin/bash

# Confirm that a record is not vacuumed if it is locked on the
# deleting node when the 3rd fast vacuuming run occurs, but is dropped
# from the lmaster delete list

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_init

db="vacuum_test.tdb"
key="key"

echo "Stall vacuuming on all nodes"
ctdb_onnode -p all "setvar VacuumInterval 99999"

echo
echo "Getting list of nodes..."
ctdb_get_all_pnns

# all_pnns is set above by ctdb_get_all_pnns()
# shellcheck disable=SC2154
first=$(echo "$all_pnns" | sed -n -e '1p')

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

echo "............................................................"
echo "Delete key ${key} on node ${non_lmaster}"
echo "Lock on non-lmaster node ${non_lmaster} during 3rd vacuuming run"
echo "............................................................"

echo

echo "Create/wipe test database ${db}"
ctdb_onnode "$first" "attach ${db}"
ctdb_onnode "$first" "wipedb ${db}"

echo "Create a record in ${db}"
ctdb_onnode "$first" "writekey ${db} ${key} value1"

echo "Migrate record to all nodes"
ctdb_onnode all "readkey ${db} ${key}"

echo "Confirm that all nodes have the record"
check_cattdb_num_records "$db" 1 "$all_pnns"

echo

echo "Delete key \"${key}\" from node ${non_lmaster}"
ctdb_onnode "$non_lmaster" "deletekey $db ${key}"

echo
echo "Do a fast vacuuming run on node ${non_lmaster}"
testprog_onnode "$non_lmaster" "ctdb-db-test vacuum ${db}"

echo
echo "Confirm that all nodes still have the record"
check_cattdb_num_records "$db" 1 "$all_pnns"

echo
echo "Do a fast vacuuming run on lmaster node ${lmaster}"
testprog_onnode "$lmaster" "ctdb-db-test vacuum ${db}"

echo
echo "Confirm that all nodes still have the record"
check_cattdb_num_records "$db" 1 "$all_pnns"

echo
echo "Lock record on non-lmaster node ${non_lmaster}"
testprog_onnode "$non_lmaster" "ctdb-db-test local-lock ${db} ${key}"
pid="${out#OK }"
ctdb_test_cleanup_pid_set "$non_lmaster" "$pid"

echo "Do a fast vacuuming run on node ${lmaster}"
testprog_onnode "$lmaster" "ctdb-db-test vacuum ${db}"

echo "Kill lock process ${pid} on node ${non_lmaster}"
try_command_on_node "$non_lmaster" "kill ${pid}"
ctdb_test_cleanup_pid_clear

echo
echo "Confirm that nodes ${lmaster} and ${non_lmaster} still have the record"
check_cattdb_num_records "$db" 1 "${lmaster} ${non_lmaster}"

vacuum_confirm_key_empty_dmaster "$lmaster" "$db" "$key"

echo

# Record has been dropped from the delete list so this will not pick it up
echo "Do a fast vacuuming run on lmaster node ${lmaster}"
testprog_onnode "$lmaster" "ctdb-db-test vacuum ${db}"

echo
echo "Confirm that nodes ${lmaster} and ${non_lmaster} still have the record"
check_cattdb_num_records "$db" 1 "${lmaster} ${non_lmaster}"

vacuum_confirm_key_empty_dmaster "$lmaster" "$db" "$key"
