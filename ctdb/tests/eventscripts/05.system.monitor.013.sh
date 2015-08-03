#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Memory check, bad situation, only swap check"

setup_memcheck 100 90

CTDB_MONITOR_MEMORY_USAGE=""
CTDB_MONITOR_SWAP_USAGE=":50"

required_result 1 <<EOF
ERROR: System swap utilization 90% >= threshold 50%
CRITICAL: Shutting down CTDB!!!
$FAKE_PROC_MEMINFO
$(ps foobar)
CTDB says BYE!
EOF

simple_test
