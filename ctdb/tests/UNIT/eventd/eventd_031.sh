#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "multiple scripts"

setup_eventd

ok_null
simple_test run 30 multi monitor

ok <<EOF
01.test              OK         DURATION DATETIME
02.test              OK         DURATION DATETIME
03.test              OK         DURATION DATETIME
EOF
simple_test status multi monitor
