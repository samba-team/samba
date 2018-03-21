#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Memory check, bad memory situation, custom memory warning"

setup

setup_script_options <<EOF
CTDB_MONITOR_MEMORY_USAGE="85:"
EOF

set_mem_usage 90 10
ok <<EOF
WARNING: System memory utilization 90% >= threshold 85%
EOF

simple_test
