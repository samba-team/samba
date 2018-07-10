#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "cancel new monitor event"

setup_eventd

ok_null
simple_test_background run 10 multi startup

required_error ECANCELED <<EOF
Event monitor in multi got cancelled
EOF
simple_test run 10 multi monitor

ok <<EOF
01.test              OK         DURATION DATETIME
02.test              OK         DURATION DATETIME
03.test              OK         DURATION DATETIME
EOF
simple_test status multi startup

required_error EINVAL <<EOF
Event monitor has never run in multi
EOF
simple_test status multi monitor
