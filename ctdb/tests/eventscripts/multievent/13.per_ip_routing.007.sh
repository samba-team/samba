#!/bin/sh

. "${EVENTSCRIPTS_TESTS_DIR}/common.sh"

define_test "1 IP configured, ipreallocated"

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

    # ipreallocated should add any missing routes
    simple_test_event "ipreallocated"

    ok <<EOF
# ip rule show
0:	from all lookup local 
${CTDB_PER_IP_ROUTING_RULE_PREF}:	from $ip lookup ctdb.$ip 
32766:	from all lookup main 
32767:	from all lookup default 
# ip route show table ctdb.$ip
$net dev $dev  scope link 
default via $gw dev $dev 
EOF

    simple_test_command dump_routes
}

