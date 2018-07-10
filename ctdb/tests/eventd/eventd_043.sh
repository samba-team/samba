#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "multiple components with timeout"

setup_eventd

ok_null
simple_test_background run 10 multi monitor

required_error ETIMEDOUT <<EOF
Event timeout in random timed out
EOF
simple_test run 10 random timeout

ok <<EOF
01.test              OK         DURATION DATETIME
02.test              OK         DURATION DATETIME
03.test              OK         DURATION DATETIME
EOF
simple_test status multi monitor

required_error ETIMEDOUT <<EOF
01.disabled          DISABLED  
02.enabled           TIMEDOUT   DATETIME
  OUTPUT: 
EOF
simple_test status random timeout
