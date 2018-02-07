#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Filesystem use check, warn situation, both checks enabled"

setup

CTDB_MONITOR_FILESYSTEM_USAGE="/var:80:90"

set_fs_usage 85
ok <<EOF
WARNING: Filesystem /var utilization 85% >= threshold 80%
EOF
simple_test
