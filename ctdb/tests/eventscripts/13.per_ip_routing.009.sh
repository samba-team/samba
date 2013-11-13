#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "All IPs configured, takeip 1 address"

setup_ctdb
setup_ctdb_policy_routing

# configure all addresses
create_policy_routing_config all default

# add routes for all 1 IP
ctdb_get_1_public_address |
while read dev ip bits ; do
    ok_null
    simple_test_event "takeip" $dev $ip $bits
done

# for 1 IP
check_routes 1 default
