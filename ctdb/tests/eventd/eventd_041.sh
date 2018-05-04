#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "multiple components"

setup_eventd

ok_null
simple_test_background run 10 multi monitor

ok_null
simple_test run 10 random monitor

ok <<EOF
01.test              OK         DURATION DATETIME
02.test              OK         DURATION DATETIME
03.test              OK         DURATION DATETIME
EOF
simple_test status multi monitor

ok <<EOF
01.disabled          DISABLED  
02.enabled           OK         DURATION DATETIME
EOF
simple_test status random monitor
