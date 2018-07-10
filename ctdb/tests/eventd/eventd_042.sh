#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "multiple components with failure"

setup_eventd

ok_null
simple_test_background run 10 multi monitor

required_error ENOEXEC <<EOF
Event failure in random failed
EOF
simple_test run 10 random failure

ok <<EOF
01.test              OK         DURATION DATETIME
02.test              OK         DURATION DATETIME
03.test              OK         DURATION DATETIME
EOF
simple_test status multi monitor

required_result 1 <<EOF
01.disabled          DISABLED  
02.enabled           ERROR      DURATION DATETIME
  OUTPUT: 
EOF
simple_test status random failure
