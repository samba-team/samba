#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "not configured"

setup_ctdb
setup_ctdb_lvs <<EOF
EOF

ok_null
simple_test
