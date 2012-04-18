#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "__auto_link_local__, takeip all on node"

setup_ctdb
setup_ctdb_policy_routing
# Override to do link local fu
CTDB_PER_IP_ROUTING_CONF="__auto_link_local__"

# Do a takeip for each IP on the "current" node
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
$net dev $dev  scope link "
    done

	ok <<EOF
# ip rule show
0:	from all lookup local ${policy_rules}
32766:	from all lookup main 
32767:	from all lookup default ${policy_routes}
EOF

    simple_test_command dump_routes
}
