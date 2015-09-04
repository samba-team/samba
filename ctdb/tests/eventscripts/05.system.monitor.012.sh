#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Memory check, good situation, all memory checks enabled"

setup_memcheck

CTDB_MONITOR_MEMORY_USAGE="80:90"
CTDB_MONITOR_SWAP_USAGE="1:50"

ok_null

simple_test
