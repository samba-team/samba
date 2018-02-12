#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "1 IP configured, takeip"

setup

# Configuration for 1 IP
create_policy_routing_config 1 default

# takeip should add routes for the given address
ctdb_get_1_public_address |
while read dev ip bits ; do
    ok_null
    simple_test_event "takeip" $dev $ip $bits
done

# Should have routes for 1 IP
check_routes 1 default
