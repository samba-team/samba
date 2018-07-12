#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "empty eventscript directory"

setup_eventd

required_error EINVAL <<EOF
Event monitor has never run in empty
EOF
simple_test status empty monitor

ok_null
simple_test run 10 empty monitor

ok_null
simple_test status empty monitor

ok_null
simple_test script list empty
