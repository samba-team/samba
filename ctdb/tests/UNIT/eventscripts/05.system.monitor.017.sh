#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Memory check (custom, both), error situation"

setup

setup_script_options <<EOF
CTDB_MONITOR_MEMORY_USAGE="70:80"
EOF

set_mem_usage 87 87
required_result 1 <<EOF
ERROR: System memory utilization 87% >= threshold 80%
$FAKE_PROC_MEMINFO
$(ps foobar)
EOF

simple_test
