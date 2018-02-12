#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "empty config, takeip"

setup

create_policy_routing_config 0

public_address=$(ctdb_get_1_public_address)

ok_null
simple_test_event "takeip" $public_address

# empty configuration file should mean there are no routes
check_routes 0
