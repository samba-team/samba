#!/bin/bash

# Confirm that a record is vacuumed if it is locked on the deleting
# node when the 2nd fast vacuuming run occurs, but vacuuming is
# delayed until the lock is released

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
echo "Lock on non-lmaster node ${non_lmaster} during 2nd vacuuming run"
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
echo "Lock record on non-lmaster node ${non_lmaster}"
testprog_onnode "$non_lmaster" "ctdb-db-test local-lock ${db} ${key}"
pid="${out#OK }"
ctdb_test_cleanup_pid_set "$non_lmaster" "$pid"

echo
echo "Do a fast vacuuming run on lmaster node ${lmaster} - THIS WILL FAIL"
status=0
testprog_onnode "$lmaster" "ctdb-db-test -t 10 vacuum ${db}" || status=$?

if [ $status -ne 110 ] ; then
	ctdb_test_fail "$out"
fi

echo "Confirm record key=\"${key}\" has dmaster=${non_lmaster}"
vacuum_test_key_dmaster "$lmaster" "$db" "$key" "$non_lmaster"

echo "Kill lock process ${pid} on node ${non_lmaster}"
try_command_on_node "$non_lmaster" "kill ${pid}"
ctdb_test_cleanup_pid_clear

echo "Wait until record is migrated to lmaster node ${lmaster}"
wait_until 30 vacuum_test_key_dmaster "$lmaster" "$db" "$key"

echo
echo "Confirm that all nodes still have the record"
check_cattdb_num_records "$db" 1 "$all_pnns"

echo "Do a fast vacuuming run on node ${lmaster}"
testprog_onnode "$lmaster" "ctdb-db-test vacuum ${db}"

echo
echo "Confirm that the record is gone from all nodes"
check_cattdb_num_records "$db" 0 "$all_pnns"
