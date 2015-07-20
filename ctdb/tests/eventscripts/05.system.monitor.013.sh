#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Memory check, bad situation, only swap check"

setup_memcheck "bad"

CTDB_MONITOR_FREE_MEMORY=""
CTDB_MONITOR_FREE_MEMORY_WARN=""
CTDB_CHECK_SWAP_IS_NOT_USED="yes"

ok <<EOF
We are swapping:
$FAKE_PROC_MEMINFO
$(ps foobar)
EOF

simple_test
