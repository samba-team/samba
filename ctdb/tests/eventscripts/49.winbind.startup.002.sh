#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "managed"

setup_winbind "down"
export CTDB_MANAGES_WINBIND="yes"

ok <<EOF
Starting winbind: OK
EOF
simple_test
