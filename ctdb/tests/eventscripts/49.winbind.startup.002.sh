#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "managed"

setup "down"

setup_script_options <<EOF
CTDB_MANAGES_WINBIND="yes"
EOF

ok <<EOF
Starting winbind: OK
EOF
simple_test
