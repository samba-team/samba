#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "managed"

setup "up"

CTDB_MANAGES_VSFTPD="yes"

ok <<EOF
Stopping vsftpd: OK
EOF
simple_test
