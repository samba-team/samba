#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Memory check, bad situation, both memory checks, causes warning"

setup_memcheck 87 0

CTDB_MONITOR_MEMORY_USAGE="80:90"
CTDB_MONITOR_SWAP_USAGE=""

ok <<EOF
WARNING: System memory utilization 87% >= threshold 80%
EOF

simple_test
