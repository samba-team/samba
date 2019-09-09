#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "__auto_link_local__, takeip all on node"

setup

# do link local fu instead of creating configuration
setup_script_options <<EOF
CTDB_PER_IP_ROUTING_CONF="__auto_link_local__"
EOF

# add routes for all addresses
ctdb_get_my_public_addresses |
while read dev ip bits ; do
    ok_null
    simple_test_event "takeip" $dev $ip $bits
done

check_routes all
