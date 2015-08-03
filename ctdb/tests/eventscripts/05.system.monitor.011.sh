#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Memory check, bad situation, no checks enabled"

setup_memcheck 100 100

CTDB_MONITOR_MEMORY_USAGE=""
CTDB_MONITOR_SWAP_USAGE=""

ok_null

simple_test
