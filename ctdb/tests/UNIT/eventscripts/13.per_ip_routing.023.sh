#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "1 IP configured, broken configuration, takeip"

setup

# Configuration for 1 IP
create_policy_routing_config 1 default

# takeip should add routes for the given address
ctdb_get_1_public_address |
while read dev ip bits ; do
    # Now add configuration breakage by changing default route into a
    # link local route with a gateway
    net=$(ipv4_host_addr_to_net "$ip" "$bits")
    sed -i -e "s@0\.0\.0\.0/0@${net}@" "$CTDB_PER_IP_ROUTING_CONF"

    ok <<EOF
RTNETLINK answers: File exists
add_routing_for_ip: failed to add route: ${net} via ${net%.*}.254 dev ${dev} table ctdb.${ip}
EOF
    simple_test_event "takeip" $dev $ip $bits
done
