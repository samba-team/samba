#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Filesystem use check, warn situation, both checks enabled"

setup_memcheck

CTDB_MONITOR_FILESYSTEM_USAGE="/var:80:90"
setup_fscheck 85
ok <<EOF
WARNING: Filesystem /var utilization 85% >= threshold 80%
EOF
simple_test
