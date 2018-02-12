#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "managed"

setup "down"

CTDB_MANAGES_VSFTPD="yes"

ok <<EOF
Starting vsftpd: OK
EOF
simple_test
