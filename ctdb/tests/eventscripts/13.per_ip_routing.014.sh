#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "1 IP configured, takeip, moveip, ipreallocated"

# We move the IP to another node but don't run releaseip.
# ipreallocated should remove the bogus routes.

setup_ctdb
setup_ctdb_policy_routing

create_policy_routing_config 1 default

ctdb_get_1_public_address |
while read dev ip bits ; do
    ok_null
    # Set up the routes for an IP that we have
    simple_test_event "takeip" $dev $ip $bits

    # Now move that IPs but don't run the associated "releaseip"
    ctdb moveip $ip 1

    # This should handle removal of the routes
    ok "Removing ip rule/routes for unhosted public address $ip"
    simple_test_event "ipreallocated"
done

# no routes left
check_routes 0
