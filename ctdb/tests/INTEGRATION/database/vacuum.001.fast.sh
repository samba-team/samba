#!/bin/bash

# Ensure that vacuuming deletes records on all nodes

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_init

vacuum_test ()
{
	local db="$1"
	local num_records="$2"
	local delete_from_lmaster="${3:-false}"

	local t
	if "$delete_from_lmaster" ; then
		t="lmaster"
	else
		t="non-lmaster"
	fi

	echo
	echo '............................................................'
	printf 'Creating %d record(s)\n' "$num_records"
	printf 'Testing vacuuming of 1 record deleted from %s\n' "$t"
	echo '............................................................'

	echo
	echo "Stall vacuuming on all nodes"
	ctdb_onnode -p all "setvar VacuumInterval 99999"

	echo
	echo "Getting list of nodes..."
	local all_pnns
	ctdb_get_all_pnns

	local first
	first=$(echo "$all_pnns" | sed -n -e '1p')

	echo
	echo "Create/wipe test database ${db}"
	ctdb_onnode "$first" "attach ${db}"
	ctdb_onnode "$first" "wipedb ${db}"

	echo
	echo "Write ${num_records} records to ${db}"
	local i
	for i in $(seq 1 "$num_records") ; do
		ctdb_onnode "$first" "writekey ${db} test${i} value${i}"
	done

	echo
	echo "Migrate record(s) to all nodes"
	for i in $(seq 1 "$num_records") ; do
		ctdb_onnode all "readkey ${db} test${i}"
	done

	echo
	echo "Confirm that all nodes have all the records"
	check_cattdb_num_records "$db" "$num_records" "$all_pnns"

	local key="test1"
	echo
	echo "Delete key ${key}"

	echo "  Find lmaster for key \"${key}\""
	testprog_onnode "$first" "ctdb-db-test get-lmaster ${key}"
	# out  is set above
	# shellcheck disable=SC2154
	lmaster="$out"
	echo "  lmaster=${lmaster}"

	if "$delete_from_lmaster" ; then
		echo "  Delete key ${key} on lmaster node ${lmaster}"
		dnode="$lmaster"
	else
		for i in $all_pnns ; do
			if [ "$i" != "$lmaster" ] ; then
				dnode="$i"
				break
			fi
		done
		echo "  Delete key ${key} on non-lmaster node ${dnode}"
	fi
	ctdb_onnode "$dnode" "deletekey ${db} ${key}"

	echo
	vacuum_confirm_key_empty_dmaster "$dnode" "$db" "$key"

	echo
	echo "Confirm all records still exist on all nodes"
	check_cattdb_num_records "$db" "$num_records" "$all_pnns"

	if ! "$delete_from_lmaster" ; then
		# Ask the lmaster to fetch the deleted record
		echo
		echo "Vacuum on non-lmaster node ${dnode}"
		testprog_onnode "$dnode" "ctdb-db-test vacuum ${db}"

		echo
		vacuum_confirm_key_empty_dmaster "$dnode" "$db" "$key"

		# Fetch the record and put it in the delete queue in
		# the main daemon for processing in next vacuuming run
		# on the lmaster
		echo
		echo "Vacuum on lmaster node ${lmaster}"
		testprog_onnode "$lmaster" "ctdb-db-test vacuum ${db}"

		echo
		echo "Confirm all records still exist on all node nodes"
		check_cattdb_num_records "$db" "$num_records" "$all_pnns"

		echo
		vacuum_confirm_key_empty_dmaster "$lmaster" "$db" "$key"
	fi

	echo
	# In the delete-from-lmaster case, the record is already in
	# the lmaster's delete-queue so only a single run is needed
	echo "Vacuum on lmaster node ${lmaster}"
	testprog_onnode "$lmaster" "ctdb-db-test vacuum ${db}"

	echo
	echo "Confirm a record has been deleted on all nodes"
	local n=$((num_records - 1))
	check_cattdb_num_records "$db" "$n" "$all_pnns"

	echo
	echo "Confirm all other records still exist with expected values"
	local i
	for i in $(seq 1 "$num_records") ; do
		local k="test${i}"
		local v="value${i}"

		if [ "$k" = "$key" ] ; then
			continue
		fi

		db_confirm_key_has_value "$first" "$db" "$k" "$v"
	done
	echo "GOOD"
}

testdb="vacuum_test.tdb"

# 1 record, delete from non-lmaster
vacuum_test "$testdb" 1 false

# 10 records, delete from non-lmaster
vacuum_test "$testdb" 10 false

# 1 record, delete from lmaster
vacuum_test "$testdb" 1 true

# 10 records, delete from lmaster
vacuum_test "$testdb" 10 true
