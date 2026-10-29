#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "fail to start without a socket on stdin"

required_result 1 <<EOF
Startup fd is not a socket
EOF
# Fail rather than hang if the event daemon starts
unit_test timeout 10 ctdb-eventd </dev/null
