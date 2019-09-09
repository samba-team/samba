#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Filesystem use check, warn situation, only error check enabled"

setup

setup_script_options <<EOF
CTDB_MONITOR_FILESYSTEM_USAGE="/var::80"
EOF

set_fs_usage 70
ok_null
simple_test
