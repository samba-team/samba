#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "managed"

setup_winbind "up"
export CTDB_MANAGES_WINBIND="yes"

ok <<EOF
Stopping winbind: OK
EOF
simple_test
