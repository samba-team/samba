#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Filesystem use check, warn situation, only error check enabled"

CTDB_MONITOR_FILESYSTEM_USAGE="/var::80"
setup_fscheck 70
ok_null
simple_test
