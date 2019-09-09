#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Single IP, restores original rt_tables"

setup

create_policy_routing_config 1 default

_rt_tables="$CTDB_SYS_ETCDIR/iproute2/rt_tables"
_rt_orig=$(TMPDIR="$CTDB_TEST_TMP_DIR" mktemp)
cp "$_rt_tables" "$_rt_orig"

ctdb_get_1_public_address | {
	read dev ip bits

	ok_null
	simple_test_event "takeip" $dev $ip $bits

	ok <<EOF
Removing ip rule for public address ${ip} for routing table ctdb.${ip}
EOF
	simple_test_event "shutdown"
}

ok_null
simple_test_command diff -u "$_rt_orig" "$_rt_tables"

check_routes 0
