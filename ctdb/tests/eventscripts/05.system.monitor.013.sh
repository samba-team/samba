#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Memory check, bad situation, custom swap critical"

setup

setup_script_options <<EOF
CTDB_MONITOR_SWAP_USAGE=":50"
EOF

set_mem_usage 100 90
required_result 1 <<EOF
WARNING: System memory utilization 100% >= threshold 80%
ERROR: System swap utilization 90% >= threshold 50%
$FAKE_PROC_MEMINFO
$(ps foobar)
EOF

simple_test
