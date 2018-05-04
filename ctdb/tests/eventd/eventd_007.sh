#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "timing out event script"

setup_eventd

required_result 62 <<EOF
Event timeout in random timed out
EOF
simple_test run 5 random timeout

required_result 62 <<EOF
01.disabled          DISABLED  
02.enabled           TIMEDOUT   DATETIME
  OUTPUT: 
EOF
simple_test status random timeout
