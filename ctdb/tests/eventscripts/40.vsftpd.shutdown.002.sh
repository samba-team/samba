#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "managed"

setup "up"

ok <<EOF
Stopping vsftpd: OK
EOF
simple_test
