#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Memory check, bad situation, only memory warning"

setup_memcheck "bad"

CTDB_MONITOR_FREE_MEMORY=""
CTDB_MONITOR_FREE_MEMORY_WARN="500"
CTDB_CHECK_SWAP_IS_NOT_USED="no"

ok <<EOF
WARNING: free memory is low - 468MB free <=  ${CTDB_MONITOR_FREE_MEMORY_WARN}MB (CTDB threshold)
EOF

simple_test
