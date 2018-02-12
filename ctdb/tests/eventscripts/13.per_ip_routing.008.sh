#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "1 IP configured, takeip twice"

setup

# create config for 1 IP
create_policy_routing_config 1 default

ctdb_get_1_public_address |
while read dev ip bits ; do
    ok_null
    simple_test_event "takeip" $dev $ip $bits

    # 2nd takeip event for the same IP should be a no-op
    ok_null
    simple_test_event "takeip" $dev $ip $bits
done

# should be routes for 1 IP
check_routes 1 default
