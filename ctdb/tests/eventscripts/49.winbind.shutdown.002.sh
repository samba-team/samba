#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "managed"

setup "up"

setup_script_options <<EOF
CTDB_MANAGES_WINBIND="yes"
EOF

ok <<EOF
Stopping winbind: OK
EOF
simple_test
