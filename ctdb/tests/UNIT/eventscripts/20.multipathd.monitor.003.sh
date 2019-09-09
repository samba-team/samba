#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 multipath devices configure to check, one down"

setup "mpatha"  "!mpathb"  "mpathc"

required_result 1 <<EOF
ERROR: multipath device "mpathb" has no active paths
multipath monitoring failed
EOF

simple_test
