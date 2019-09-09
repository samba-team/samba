#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "1 IP configured, releaseip of unassigned"

setup

export IP_ROUTE_BAD_TABLE_ID=true

create_policy_routing_config 1 default

ctdb_get_1_public_address |
{
    read dev ip bits

    ok <<EOF
WARNING: Failed to delete policy routing rule
  Command "ip rule del from $ip pref $CTDB_PER_IP_ROUTING_RULE_PREF table ctdb.$ip" failed:
  Error: argument ctdb.$ip is wrong: invalid table ID
  Error: argument ctdb.$ip is wrong: table id value is invalid
EOF

    simple_test_event "releaseip" $dev $ip $bits
}


# there should be no routes
check_routes 0
