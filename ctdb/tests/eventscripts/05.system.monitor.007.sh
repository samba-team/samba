#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Filesystem use check, good situation, both checks enabled, multiple filesystems"

setup_memcheck

CTDB_MONITOR_FILESYSTEM_USAGE="/var:80:90 /:90:95"
setup_fscheck
ok_null
simple_test
