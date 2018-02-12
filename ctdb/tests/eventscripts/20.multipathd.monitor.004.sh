#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 multipath devices configure to check, multipath hangs"

setup "mpatha"  "!mpathb"  "mpathc"
export FAKE_MULTIPATH_HANG="yes"

required_result 1 <<EOF
ERROR: callout to multipath checks hung
multipath monitoring failed
EOF

simple_test
