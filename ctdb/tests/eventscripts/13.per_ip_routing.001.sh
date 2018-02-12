#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "not configured"

setup

CTDB_PER_IP_ROUTING_CONF=""

ok_null
simple_test_event "takeip"

ok_null
simple_test_event "ipreallocate"

check_routes 0
