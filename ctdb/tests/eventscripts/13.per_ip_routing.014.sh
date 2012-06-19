#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "1 IP configured, takeip, moveip, ipreallocated"

# We move the IP to another node but don't run releaseip.
# ipreallocated should remove the bogus routes.

setup_ctdb
setup_ctdb_policy_routing

ctdb_get_1_public_address |
{
    read dev ip bits

    net=$(ipv4_host_addr_to_net "$ip" "$bits")
    gw="${net%.*}.1" # a dumb, calculated default

    cat >"$CTDB_PER_IP_ROUTING_CONF" <<EOF
$ip $net
$ip 0.0.0.0/0 $gw
EOF

    ok_null

    # Set up the routes for an IP that we have
    simple_test_event "takeip" $dev $ip $bits

    # Now move that IPs but don't run the associated "releaseip"
    ctdb moveip $ip 1

    ok <<EOF
Removing ip rule/routes for unhosted public address 10.0.0.3
EOF

    simple_test_event "ipreallocated"

    ok <<EOF
# ip rule show
0:	from all lookup local 
32766:	from all lookup main 
32767:	from all lookup default 
EOF

    simple_test_command dump_routes
}
