#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "queue events"

setup_eventd

ok_null
simple_test_background run 10 multi queue1

ok_null
simple_test run 10 multi queue2

ok <<EOF
01.test              OK         DURATION DATETIME
02.test              OK         DURATION DATETIME
03.test              OK         DURATION DATETIME
EOF
simple_test status multi queue1

ok <<EOF
01.test              OK         DURATION DATETIME
02.test              OK         DURATION DATETIME
03.test              OK         DURATION DATETIME
EOF
simple_test status multi queue2
