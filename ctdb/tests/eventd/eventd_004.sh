#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "disabled event script"

setup_eventd

ok_null
simple_test script disable random 01.disabled

ok_null
simple_test script disable random 01.disabled

ok_null
simple_test script enable random 01.disabled

ok_null
simple_test script disable random 01.disabled

required_error EINVAL <<EOF
Event monitor has never run in random
EOF
simple_test status random monitor

ok_null
simple_test run 10 random monitor

ok <<EOF
01.disabled          DISABLED  
02.enabled           OK         DURATION DATETIME
EOF
simple_test status random monitor
