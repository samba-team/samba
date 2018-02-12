#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "1 IP configured, takeip, releaseip, ipreallocated"

# This partly tests the test infrastructure.  If the (stub) "ctdb
# moveip" doesn't do anything then the IP being released will still be
# on the node and the ipreallocated event will add the routes back.

setup

create_policy_routing_config 1 default

ctdb_get_1_public_address |
while read dev ip bits ; do
    ok_null
    simple_test_event "takeip" $dev $ip $bits

    ok_null
    ctdb moveip $ip 1
    simple_test_event "releaseip" $dev $ip $bits

    ok_null
    simple_test_event "ipreallocated"
done

# all routes should have been removed and not added back
check_routes 0
