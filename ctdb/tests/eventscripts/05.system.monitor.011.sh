#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Memory check, bad situation, no checks enabled"

setup_memcheck "bad"

CTDB_MONITOR_FREE_MEMORY=""
CTDB_MONITOR_FREE_MEMORY_WARN=""
CTDB_CHECK_SWAP_IS_NOT_USED="no"

ok_null

simple_test
