#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "eventscript directory with random files"

setup_eventd

required_result 22 <<EOF
Script README is invalid in random
EOF
simple_test script enable random README

required_result 22 <<EOF
Script a is invalid in random
EOF
simple_test script disable random a

required_result 2 <<EOF
Script 00.foobar does not exist in random
EOF
simple_test script enable random 00.foobar

required_result 22 <<EOF
Event monitor has never run in random
EOF
simple_test status random monitor

ok <<EOF
EOF
simple_test run 10 random monitor

ok <<EOF
01.disabled          DISABLED  
02.enabled           OK         DURATION DATETIME
EOF
simple_test status random monitor
