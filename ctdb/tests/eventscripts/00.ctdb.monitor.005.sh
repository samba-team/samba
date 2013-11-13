#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Memory check, bad situation, only memory critical"

setup_memcheck "bad"

CTDB_MONITOR_FREE_MEMORY="500"
CTDB_MONITOR_FREE_MEMORY_WARN=""
CTDB_CHECK_SWAP_IS_NOT_USED="no"

ok <<EOF
CRITICAL: OOM - 468MB free <= ${CTDB_MONITOR_FREE_MEMORY}MB (CTDB threshold)
CRITICAL: Shutting down CTDB!!!
$FAKE_PROC_MEMINFO
$(ps foobar)
CTDB says BYE!
EOF

simple_test
