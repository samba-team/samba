#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "1 IP configured, ipreallocated"

setup

# create config for 1 IP
create_policy_routing_config 1 default

# no takeip, but ipreallocated should add any missing routes
ok_null
simple_test_event "ipreallocated"

# should have routes for 1 IP
check_routes 1 default
