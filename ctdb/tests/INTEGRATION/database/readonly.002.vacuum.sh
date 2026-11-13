#!/usr/bin/env bash

# Ensure vacuuming does not delete a record with read-only delegations
#
# If the lmaster is also the dmaster of an empty record that was never
# migrated with data, a full vacuuming run deletes the record directly.
# If the record has read-only delegations, the copies on the other
# nodes stay.  When the lmaster then recreates the record and stores
# new data, the record has no delegations to revoke, so the other
# nodes keep reading their stale read-only copies.
#
# 1. Create an empty record on its lmaster
# 2. Fetch a read-only copy to another node
# 3. Run a full vacuuming run on the lmaster
# 4. Store value1 on the lmaster
# 5. Confirm that a read-only fetch on the other node returns value1

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_init

db="ro_vacuum_test.tdb"
key="test1"

echo "Getting list of nodes..."
ctdb_get_all_pnns

echo "Create/wipe test database ${db}, enable read-only delegations"
ctdb_onnode 0 "attach ${db}"
ctdb_onnode 0 "wipedb ${db}"
ctdb_onnode all "setdbreadonly ${db}"

echo "Determine lmaster node for key"
testprog_onnode 0 "ctdb-db-test get-lmaster ${key}"
# $out is set above by testprog_onnode()
# shellcheck disable=SC2154
lmaster="$out"
echo "lmaster=${lmaster}"

other=""
# all_pnns is set above by ctdb_get_all_pnns()
# shellcheck disable=SC2154
for n in $all_pnns; do
	if [ "$n" != "$lmaster" ]; then
		other="$n"
		break
	fi
done

echo
echo "Create empty key(${key}) on lmaster ${lmaster}"
ctdb_onnode "$lmaster" "readkey ${db} ${key}"
db_test_key_dmaster "$lmaster" "$db" "$key"

echo "Fetch a read-only copy to node ${other}"
ctdb_onnode "$other" "readkey ${db} ${key} readonly"
db_test_key_has_flag "$lmaster" "$db" "$key" RO_HAVE_DELEGATIONS
db_test_key_has_flag "$other" "$db" "$key" RO_HAVE_READONLY

echo
echo "Full vacuuming run on lmaster ${lmaster}"
testprog_onnode "$lmaster" "ctdb-db-test vacuum ${db} full"

echo
echo "Store key(${key}) data(value1) on lmaster ${lmaster}"
ctdb_onnode "$lmaster" "writekey ${db} ${key} value1"

echo "Read-only fetch on node ${other}"
ctdb_onnode "$other" "readkey ${db} ${key} readonly"
# $out is set above by ctdb_onnode()
# shellcheck disable=SC2154
val=$(echo "$out" | sed -n 's|^Data: size:.* ptr:\[\(.*\)\]$|\1|p')
if [ "$val" != "value1" ]; then
	testprog_onnode "$other" "ctdb-db-test local-read ${db} ${key}"
	# $outfile is set above by testprog_onnode()
	# shellcheck disable=SC2154
	cat "$outfile"
	ctdb_test_fail "BAD: node ${other} read \"${val}\" (not \"value1\")"
fi

echo "GOOD: node ${other} read value1"
