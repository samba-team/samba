#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "testparm times out"

setup

timeout_trigger "yes"
required_result 1 <<EOF
ERROR: smb.conf cache create failed - testparm command timed out
EOF
simple_test
