#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Not managed, clamd not listening"

setup

setup_script_options <<EOF
CTDB_MANAGES_CLAMD=no
CTDB_CLAMD_SOCKET="/var/run/clamd.sock"
EOF

ok_null
simple_test
