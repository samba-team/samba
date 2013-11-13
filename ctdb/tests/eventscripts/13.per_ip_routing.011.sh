#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "__auto_link_local__, takeip all on node"

setup_ctdb
setup_ctdb_policy_routing

# do link local fu instead of creating configuration
export CTDB_PER_IP_ROUTING_CONF="__auto_link_local__"

# add routes for all addresses
ctdb_get_my_public_addresses |
while read dev ip bits ; do
    ok_null
    simple_test_event "takeip" $dev $ip $bits
done

check_routes all
