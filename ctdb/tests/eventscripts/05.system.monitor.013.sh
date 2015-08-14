#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Memory check, bad situation, custom swap critical"

setup_memcheck 100 90

CTDB_MONITOR_MEMORY_USAGE=""
CTDB_MONITOR_SWAP_USAGE=":50"

required_result 1 <<EOF
WARNING: System memory utilization 100% >= threshold 80%
ERROR: System swap utilization 90% >= threshold 50%
$FAKE_PROC_MEMINFO
$(ps foobar)
EOF

simple_test
