#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Memory check, bad situation, only memory critical"

setup_memcheck 90 0

CTDB_MONITOR_MEMORY_USAGE=":85"
CTDB_MONITOR_SWAP_USAGE=""

required_result 1 <<EOF
ERROR: System memory utilization 90% >= threshold 85%
CRITICAL: Shutting down CTDB!!!
$FAKE_PROC_MEMINFO
$(ps foobar)
CTDB says BYE!
EOF

simple_test
