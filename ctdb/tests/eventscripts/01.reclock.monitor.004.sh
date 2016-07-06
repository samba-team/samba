#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "set, doesn't exist, 4 times"

setup_reclock
rm -f "$CTDB_RECOVERY_LOCK"

ok_null
simple_test
simple_test
simple_test

required_result 1 <<EOF
ERROR: 4 consecutive failures checking reclock
EOF
simple_test
