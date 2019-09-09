#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "run through failure"

setup_eventd

export CTDB_EVENT_RUN_ALL=1

required_error ENOEXEC <<EOF
Event event1 in multi failed
EOF
simple_test run 10 multi event1

required_result 1 <<EOF
01.test              OK         DURATION DATETIME
02.test              ERROR      DURATION DATETIME
  OUTPUT: 
03.test              OK         DURATION DATETIME
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
