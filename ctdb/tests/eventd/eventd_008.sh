#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "capture event script output"

setup_eventd

required_result 8 <<EOF
Event verbosefailure in random failed
EOF
simple_test run 10 random verbosefailure with some args

required_result 1 <<EOF
01.disabled          DISABLED  
02.enabled           ERROR      DURATION DATETIME
  OUTPUT: args: verbosefailure with some args
EOF
simple_test status random verbosefailure
