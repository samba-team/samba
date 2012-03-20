#!/bin/sh

. "${EVENTSCRIPTS_TESTS_DIR}/common.sh"

define_test "All IPs configured, takeip all on node"

setup_ctdb
setup_ctdb_policy_routing

# First setup the policy routing config for all possible IPs
ctdb_get_all_public_addresses |
while read dev ip bits ; do
    net=$(ipv4_host_addr_to_net "$ip" "$bits")
    gw="${net%.*}.1" # a dumb, calculated default

    cat <<EOF
$ip $net
$ip 0.0.0.0/0 $gw
EOF
done >"$CTDB_PER_IP_ROUTING_CONF"

# Now do a takeip for each IP on the "current" node
ctdb_get_my_public_addresses |
{
    policy_rules=""
    policy_routes=""
    while read dev ip bits ; do

	net=$(ipv4_host_addr_to_net "$ip" "$bits")
	gw="${net%.*}.1" # a dumb, calculated default

	ok_null

	simple_test_event "takeip" $dev $ip $bits

	policy_rules="${policy_rules}
${CTDB_PER_IP_ROUTING_RULE_PREF}:	from $ip lookup ctdb.$ip "
	policy_routes="${policy_routes}
# ip route show table ctdb.$ip
$net dev $dev  scope link 
default via $gw dev $dev "
    done

	ok <<EOF
# ip rule show
0:	from all lookup local ${policy_rules}
32766:	from all lookup main 
32767:	from all lookup default ${policy_routes}
EOF

    simple_test_command dump_routes
}
