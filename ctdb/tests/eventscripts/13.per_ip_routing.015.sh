#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "1 IP configured, releaseip of unassigned"

setup_ctdb
setup_ctdb_policy_routing

export IP_ROUTE_BAD_TABLE_ID=true

ctdb_get_1_public_address |
{
    read dev ip bits

    net=$(ipv4_host_addr_to_net "$ip" "$bits")
    gw="${net%.*}.1" # a dumb, calculated default

    cat >"$CTDB_PER_IP_ROUTING_CONF" <<EOF
$ip $net
$ip 0.0.0.0/0 $gw
EOF

    ok <<EOF
WARNING: Failed to delete policy routing rule
  Command "ip rule del from $ip pref $CTDB_PER_IP_ROUTING_RULE_PREF table ctdb.$ip" failed:
  Error: argument ctdb.$ip is wrong: invalid table ID
  Error: argument ctdb.$ip is wrong: table id value is invalid
EOF

    simple_test_event "releaseip" $dev $ip $bits

    ok <<EOF
# ip rule show
0:	from all lookup local 
32766:	from all lookup main 
32767:	from all lookup default 
EOF

    simple_test_command dump_routes
}
