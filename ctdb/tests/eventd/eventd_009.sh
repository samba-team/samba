#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "eventscript directory with links"

setup_eventd

ok_null
simple_test run 10 data failure

ok_null
simple_test script enable data 01.dummy

required_result 8 <<EOF
Event failure in data failed
EOF
simple_test run 10 data failure

required_result 1 <<EOF
01.dummy             ERROR      DURATION DATETIME
  OUTPUT: 
EOF
simple_test status data failure

ok_null
simple_test run 10 data monitor

ok <<EOF
01.dummy             OK         DURATION DATETIME
EOF
simple_test status data monitor

ok_null
simple_test script disable data 01.dummy

ok_null
simple_test run 10 data failure
