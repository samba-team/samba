#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "1 IP configured, releaseip of unassigned"

setup

create_policy_routing_config 1 default

ctdb_get_1_public_address |
while read dev ip bits ; do
    ok <<EOF
WARNING: Failed to delete policy routing rule
  Command "ip rule del from $ip pref $CTDB_PER_IP_ROUTING_RULE_PREF table ctdb.$ip" failed:
  RTNETLINK answers: No such file or directory
EOF

    simple_test_event "releaseip" $dev $ip $bits
done

# there should be no routes
check_routes 0
