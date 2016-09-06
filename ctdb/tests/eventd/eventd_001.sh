#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "empty eventscript directory"

setup_eventd

required_result 0 <<EOF
No event scripts found
EOF
simple_test script list

required_result 0 <<EOF
EOF
simple_test run monitor 30

required_result 0 <<EOF
Event monitor has never run
EOF
simple_test status monitor

required_result 0 <<EOF
Event monitor has never passed
EOF
simple_test status monitor lastpass

required_result 0 <<EOF
Event monitor has never failed
EOF
simple_test status monitor lastfail
