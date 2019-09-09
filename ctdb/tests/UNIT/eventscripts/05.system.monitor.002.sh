#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Filesystem use check, good situation, 1 error check enabled"

setup

setup_script_options <<EOF
CTDB_MONITOR_FILESYSTEM_USAGE="/var::80"
EOF

ok_null
simple_test
