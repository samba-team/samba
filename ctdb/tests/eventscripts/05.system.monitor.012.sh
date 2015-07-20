#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Memory check, good situation, all enabled"

setup_memcheck

CTDB_MONITOR_FREE_MEMORY="500"
CTDB_MONITOR_FREE_MEMORY_WARN="1000"
CTDB_CHECK_SWAP_IS_NOT_USED="yes"

ok_null

simple_test
