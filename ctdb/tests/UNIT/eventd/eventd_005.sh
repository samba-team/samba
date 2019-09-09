#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "enabled event script"

setup_eventd

ok_null
simple_test script enable random 02.enabled

ok_null
simple_test script enable random 02.enabled

ok_null
simple_test run 10 random monitor

ok <<EOF
01.disabled          DISABLED  
02.enabled           OK         DURATION DATETIME
EOF
simple_test status random monitor

ok_null
simple_test script enable random 01.disabled

ok_null
simple_test run 10 random monitor

ok <<EOF
01.disabled          OK         DURATION DATETIME
02.enabled           OK         DURATION DATETIME
EOF
simple_test status random monitor
