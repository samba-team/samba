#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "empty config, ipreallocated"

setup

create_policy_routing_config 0

# ipreallocated should silently add any missing routes
ok_null
simple_test_event "ipreallocated"

# empty configuration file should mean there are no routes
check_routes 0
