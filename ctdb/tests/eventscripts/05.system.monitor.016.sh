#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Memory check, bad situation, both memory checks, causes warning"

setup

CTDB_MONITOR_MEMORY_USAGE="80:90"
CTDB_MONITOR_SWAP_USAGE=""

set_mem_usage 87 0
ok <<EOF
WARNING: System memory utilization 87% >= threshold 80%
EOF

simple_test
