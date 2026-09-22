#!/usr/bin/env bash

# Verify that 'ctdb pushrecord' works as expected with the lmaster
# role disabled on a node

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_init

testdb="push_record_test.tdb"
key="key123"
val="val456"

select_test_node

lmaster_disabled_node=""
ctdb_get_all_pnns
# $all_pnns set above by ctdb_get_all_pnns()
# shellcheck disable=SC2154
for n in $all_pnns; do
	# $test_node set above by select_test_node()
	# shellcheck disable=SC2154
	if [ "$n" != "$test_node" ]; then
		lmaster_disabled_node="$n"
		break
	fi
done

if [ -z "$lmaster_disabled_node" ]; then
	ctdb_test_error "Unable to select lmaster disabled node"
fi
echo "Selected lmaster disabled node ${lmaster_disabled_node}"

echo
echo "Create test database ${testdb}"
ctdb_onnode "$test_node" "attach ${testdb}"

echo "Wipe test database"
ctdb_onnode "$test_node" "wipedb ${testdb}"

echo
generation_get "$test_node"

echo "Switch off lmaster role on node ${lmaster_disabled_node}"
ctdb_onnode "$lmaster_disabled_node" "setlmasterrole off"

echo
# This will mean recovery has occurred and the VNN map has been
# updated
wait_until_generation_has_changed "$test_node"

echo "Push a record ${key}=${val} via node ${test_node}"
ctdb_onnode "$test_node" "pushrecord ${testdb} ${key} ${val}"

echo
check_cattdb_num_records "$testdb" 1 "$all_pnns" || exit 1

# Convert to single line, getting rid of embedded newlines
nodes=$(echo "$all_pnns" | xargs)

echo
echo "Checking dmaster value in record on nodes: ${nodes}"
for n in $all_pnns; do
	db_test_key_dmaster "$n" "$testdb" "$key" "$test_node"
done

echo
echo "Checking RSN value in record on nodes: ${nodes}"
for n in $all_pnns; do
	rsn=3
	if [ "$n" = "$test_node" ]; then
		rsn=$((rsn + 1))
	fi
	db_test_key_attr "$n" "$testdb" "$key" "rsn" "$rsn"
done

echo
db_confirm_key_has_value "$lmaster_disabled_node" "$testdb" "$key" "$val"
echo "GOOD: Found ${key}=${val}"
