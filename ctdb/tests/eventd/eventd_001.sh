#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "non-existent eventscript directory"

setup_eventd

required_error ENOENT <<EOF
Event dir for foobar does not exist
EOF
simple_test status foobar monitor

required_error ENOENT <<EOF
Event dir for foobar does not exist
EOF
simple_test run 10 foobar monitor

required_error ENOENT <<EOF
Script 01.test does not exist in foobar
EOF
simple_test script enable foobar 01.test

required_error ENOENT <<EOF
Command script list finished with result=$(errcode ENOENT)
EOF
simple_test script list foobar
