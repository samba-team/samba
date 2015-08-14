#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Memory check, bad memory situation, custom memory warning"

setup_memcheck 90 10

CTDB_MONITOR_MEMORY_USAGE="85:"
CTDB_MONITOR_SWAP_USAGE=""

ok <<EOF
WARNING: System memory utilization 90% >= threshold 85%
EOF

simple_test
