#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "failing event script"

setup_eventd

required_error ENOEXEC <<EOF
Event failure in random failed
EOF
simple_test run 10 random failure

required_result 1 <<EOF
01.disabled          DISABLED  
02.enabled           ERROR      DURATION DATETIME
  OUTPUT: 
EOF
simple_test status random failure
