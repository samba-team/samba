#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Filesystem use check, error situation, both checks enabled"

setup

setup_script_options <<EOF
CTDB_MONITOR_FILESYSTEM_USAGE="/var:80:90"
EOF

set_fs_usage 95
required_result 1 <<EOF
ERROR: Filesystem /var utilization 95% >= threshold 90%
EOF
simple_test
