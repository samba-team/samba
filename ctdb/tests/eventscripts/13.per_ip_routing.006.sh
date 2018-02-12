#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "1 IP configured, takeip, releaseip"

setup

# create config for 1 IP
create_policy_routing_config 1 default

ctdb_get_1_public_address |
while read dev ip bits ; do
    # takeip adds routes
    ok_null
    simple_test_event "takeip" $dev $ip $bits

    # releaseip removes routes
    ok_null
    simple_test_event "releaseip" $dev $ip $bits
done

# should have no routes
check_routes 0
