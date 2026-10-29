#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "event script stdin is not a socket"

setup_eventd

ok_null
simple_test run 10 stdin monitor

ok <<EOF
01.stdin             OK         DURATION DATETIME
EOF
simple_test status stdin monitor
