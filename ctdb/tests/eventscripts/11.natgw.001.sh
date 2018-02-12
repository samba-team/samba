#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "not configured"

setup

ok_null
simple_test_event "ipreallocate"

check_routes 0
