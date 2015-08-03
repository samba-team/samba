#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Memory check, bad situation, only memory warning"

setup_memcheck 90 10

CTDB_MONITOR_FREE_MEMORY=""
CTDB_MONITOR_FREE_MEMORY_WARN="85"
CTDB_CHECK_SWAP_IS_NOT_USED="no"

ok <<EOF
WARNING: memory usage is excessive - 90% >=  85% (CTDB threshold)
EOF

simple_test
