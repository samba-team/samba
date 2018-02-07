#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Filesystem use check, good situation, both checks enabled, multiple filesystems"

setup

CTDB_MONITOR_FILESYSTEM_USAGE="/var:80:90 /:90:95"

ok_null
simple_test
