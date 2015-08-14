#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Filesystem use check, error situation, no checks enabled"

setup_memcheck

CTDB_MONITOR_FILESYSTEM_USAGE=""
setup_fscheck 100
ok_null
simple_test
