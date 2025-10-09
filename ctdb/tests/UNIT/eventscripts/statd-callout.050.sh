#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "confirm sm-notify is ignored"

setup

ok_null
simple_test_event "startup"
simple_test_event "sm-notify" "192.168.10.104" "client10" "9999"
