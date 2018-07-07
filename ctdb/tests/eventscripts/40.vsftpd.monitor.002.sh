#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "managed, down - once, twice"

setup "down"

ok <<EOF
vsftpd not listening on TCP port 21
WARNING: vsftpd not listening but less than 2 consecutive failures, not unhealthy yet
EOF
simple_test

required_result 1 <<EOF
vsftpd not listening on TCP port 21
ERROR: 2 consecutive failures for vsftpd, marking node unhealthy
EOF
simple_test
