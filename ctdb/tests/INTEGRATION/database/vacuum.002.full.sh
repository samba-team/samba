#!/bin/bash

# Ensure a full vacuuming run deletes records

# Create some records, delete some of them on their lmaster (with a
# test tool that doesn't do SCHEDULE_FOR_DELETION), run some fast
# vacuuming runs (to ensure they don't delete records that haven't
# been added to the delete queue) and then try a full vacuuming run,
# which will actually do a traverse of the database to find empty
# records and delete them.  Confirm that records that haven't been
# deleted are still there, with expected values.

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
echo "Create records in ${db}"
for i in $(seq 1 10) ; do
	ctdb_onnode "$first" "writekey ${db} delete${i} value${i}"
	ctdb_onnode "$first" "writekey ${db} keep${i} value${i}"
done

echo
echo "Migrate record(s) to all nodes"
for i in $(seq 1 10) ; do
	ctdb_onnode all "readkey ${db} delete${i}"
	ctdb_onnode all "readkey ${db} keep${i}"
done

echo
echo "Confirm that all nodes have all the records"
check_cattdb_num_records "$db" 20 "$all_pnns"

echo
echo "Delete all 10 records from their lmaster node"
for i in $(seq 1 10) ; do
	key="delete${i}"

	testprog_onnode "$first" "ctdb-db-test get-lmaster ${key}"
	# $out is set above by testprog_onnode()
	# shellcheck disable=SC2154
	lmaster="$out"

	echo
	echo "Delete ${key} from lmaster node ${lmaster}"
	testprog_onnode "$lmaster" \
			     "ctdb-db-test fetch-local-delete $db ${key}"

	vacuum_confirm_key_empty_dmaster "$lmaster" "$db" "$key"
done

echo "Do fast vacuuming run on all nodes"
testprog_onnode "all" "ctdb-db-test vacuum ${db}"

echo
echo "Confirm all records still exist on all nodes"
check_cattdb_num_records "$db" 20 "$all_pnns"

echo
echo "Do full vacuuming run on all nodes"
testprog_onnode "all" "ctdb-db-test vacuum ${db} full"

echo
echo "Confirm 10 records exist on all nodes"
check_cattdb_num_records "$db" 10 "$all_pnns"

echo
echo "Confirm  that remaining records still exist with expected values"
for i in $(seq 1 10) ; do
	k="keep${i}"
	v="value${i}"

	db_confirm_key_has_value "$first" "$db" "$k" "$v"
done
echo "GOOD"
