#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "non-existent eventscript directory"

setup_eventd

required_result 2 <<EOF
Event dir for foobar does not exist
EOF
simple_test status foobar monitor

required_result 2 <<EOF
Event dir for foobar does not exist
EOF
simple_test run 10 foobar monitor

required_result 2 <<EOF
Script 01.test does not exist in foobar
EOF
simple_test script enable foobar 01.test
