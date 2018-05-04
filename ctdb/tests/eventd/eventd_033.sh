#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "timeouts with multiple scripts"

setup_eventd

required_result 62 <<EOF
Event timeout1 in multi timed out
EOF
simple_test run 5 multi timeout1

required_result 62 <<EOF
01.test              TIMEDOUT   DATETIME
  OUTPUT: 
EOF
simple_test status multi timeout1

required_result 62 <<EOF
Event timeout2 in multi timed out
EOF
simple_test run 5 multi timeout2

required_result 62 <<EOF
01.test              OK         DURATION DATETIME
02.test              TIMEDOUT   DATETIME
  OUTPUT: 
EOF
simple_test status multi timeout2

required_result 62 <<EOF
Event timeout3 in multi timed out
EOF
simple_test run 5 multi timeout3

required_result 62 <<EOF
01.test              OK         DURATION DATETIME
02.test              OK         DURATION DATETIME
03.test              TIMEDOUT   DATETIME
  OUTPUT: 
EOF
simple_test status multi timeout3
