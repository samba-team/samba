#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "multiple events"

setup_eventd

ok_null
simple_test run 10 random monitor

ok <<EOF
01.disabled          DISABLED  
02.enabled           OK         DURATION DATETIME
EOF
simple_test status random monitor

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

required_error ENOEXEC <<EOF
Event verbosefailure in random failed
EOF
simple_test run 10 random verbosefailure

required_result 1 <<EOF
01.disabled          DISABLED  
02.enabled           ERROR      DURATION DATETIME
  OUTPUT: args: verbosefailure
EOF
simple_test status random verbosefailure
