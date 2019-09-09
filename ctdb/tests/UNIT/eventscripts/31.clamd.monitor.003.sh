#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Managed, clamd listening"

setup

setup_script_options <<EOF
CTDB_CLAMD_SOCKET="/var/run/clamd.sock"
EOF

unix_socket_listening "$CTDB_CLAMD_SOCKET"

ok_null
simple_test
