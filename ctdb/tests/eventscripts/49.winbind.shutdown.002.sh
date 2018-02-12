#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "managed"

setup "up"

CTDB_MANAGES_WINBIND="yes"

ok <<EOF
Stopping winbind: OK
EOF
simple_test
