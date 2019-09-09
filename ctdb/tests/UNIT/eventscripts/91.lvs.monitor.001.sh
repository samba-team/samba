#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "not configured"

setup <<EOF
EOF

ok_null
simple_test
