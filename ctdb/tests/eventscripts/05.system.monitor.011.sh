#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Memory check, bad situation, default checks enabled"

setup_memcheck 100 100

CTDB_MONITOR_MEMORY_USAGE=""
CTDB_MONITOR_SWAP_USAGE=""

ok <<EOF
WARNING: System memory utilization 100% >= threshold 80%
WARNING: System swap utilization 100% >= threshold 25%
EOF
simple_test
