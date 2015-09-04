#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Filesystem use check, error situation, 1 error check enabled"

setup_memcheck

CTDB_MONITOR_FILESYSTEM_USAGE="/var::80"
setup_fscheck 90
required_result 1 <<EOF
ERROR: Filesystem /var utilization 90% >= threshold 80%
EOF
simple_test
