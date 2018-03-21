#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "managed"

setup "down"

setup_script_options <<EOF
CTDB_MANAGES_VSFTPD="yes"
EOF

ok <<EOF
Starting vsftpd: OK
EOF
simple_test
