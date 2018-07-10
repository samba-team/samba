#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "failures with multiple scripts"

setup_eventd

required_error ENOEXEC <<EOF
Event event1 in multi failed
EOF
simple_test run 10 multi event1

required_result 1 <<EOF
01.test              OK         DURATION DATETIME
02.test              ERROR      DURATION DATETIME
  OUTPUT: 
EOF
simple_test status multi event1

required_error ENOEXEC <<EOF
Event event2 in multi failed
EOF
simple_test run 10 multi event2

required_result 2 <<EOF
01.test              OK         DURATION DATETIME
02.test              OK         DURATION DATETIME
03.test              ERROR      DURATION DATETIME
  OUTPUT: 
EOF
simple_test status multi event2

required_error ENOEXEC <<EOF
Event event3 in multi failed
EOF
simple_test run 10 multi event3

required_result 3 <<EOF
01.test              ERROR      DURATION DATETIME
  OUTPUT: 
EOF
simple_test status multi event3
