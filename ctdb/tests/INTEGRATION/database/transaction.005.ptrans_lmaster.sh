#!/usr/bin/env bash

# Verify that 'ctdb ptrans' works as expected with the lmaster role
# disabled on a node

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_init

testdb="ptrans_test.tdb"
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
echo "Create persistent test database ${testdb}"
ctdb_onnode "$test_node" "attach ${testdb} persistent"

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

echo "Add a record ${key}=${val} via node ${test_node}"
echo "\"${key}\" \"${val}\"" | ctdb_onnode -i "$test_node" "ptrans ${testdb}"

echo
check_cattdb_num_records "$testdb" 1 "$all_pnns" || exit 1

echo
ctdb_onnode "$lmaster_disabled_node" "pfetch ${testdb} ${key}"
# $out set above by ctdb_onnode()
# shellcheck disable=SC2154
if [ "$out" != "$val" ]; then
	ctdb_test_fail "BAD: Failed to find ${key}=${val} in...
$out"
fi
echo "GOOD: Found ${key}=${val}"
