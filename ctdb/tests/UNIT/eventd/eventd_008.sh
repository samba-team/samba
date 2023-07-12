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

ok_null
simple_test run 10 random verbose

ok <<EOF
01.disabled          DISABLED  
02.enabled           OK         DURATION DATETIME
  OUTPUT: Running event verbose
EOF
simple_test status random verbose

ok_null
simple_test run 10 random verbosemultiline

ok <<EOF
01.disabled          DISABLED  
02.enabled           OK         DURATION DATETIME
  OUTPUT: Running event verbosemultiline
There are multiple output lines

^^^ including blank lines...
EOF
simple_test status random verbosemultiline

required_result 8 <<EOF
Event verbosemultilinefailure in random failed
EOF
simple_test run 10 random verbosemultilinefailure with some args

required_result 2 <<EOF
01.disabled          DISABLED  
02.enabled           ERROR      DURATION DATETIME
  OUTPUT: Failing event verbosemultilinefailure
There are multiple output lines

args: verbosemultilinefailure with some args
EOF
simple_test status random verbosemultilinefailure
