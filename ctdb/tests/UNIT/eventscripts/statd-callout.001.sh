#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "single add-client"

setup

ok_null
simple_test_event "add-client" "192.168.123.45"
simple_test_event "update"

check_ctdb_tdb_statd_state "192.168.123.45"
