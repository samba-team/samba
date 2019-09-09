#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "All IPs configured, takeip on all nodes"

setup

# create config for all IPs
create_policy_routing_config all default

ctdb_get_my_public_addresses |
while read dev ip bits ; do
    ok_null
    simple_test_event "takeip" $dev $ip $bits
done

# should have routes for all IPs
check_routes all default
