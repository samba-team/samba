#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "managed"

setup "up"

setup_script_options <<EOF
CTDB_MANAGES_HTTPD="yes"
EOF

ok <<EOF
Stopping httpd: OK
EOF
simple_test
