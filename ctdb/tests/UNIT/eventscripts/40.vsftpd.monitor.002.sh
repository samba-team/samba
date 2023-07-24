#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "up once, down with recovery"

setup "up"

ok_null
simple_test

setup "down"

ok <<EOF
vsftpd not listening on TCP port 21
WARNING: vsftpd listening on TCP port 21: fail count 1 >= threshold 1
EOF
simple_test

setup "up"

ok <<EOF
NOTICE: vsftpd listening on TCP port 21: no longer failing
EOF
simple_test

setup "down"

ok <<EOF
vsftpd not listening on TCP port 21
WARNING: vsftpd listening on TCP port 21: fail count 1 >= threshold 1
EOF
simple_test

required_result 1 <<EOF
vsftpd not listening on TCP port 21
ERROR: vsftpd listening on TCP port 21: fail count 2 >= threshold 2
EOF
simple_test

required_result 1 <<EOF
vsftpd not listening on TCP port 21
ERROR: vsftpd listening on TCP port 21: fail count 3 >= threshold 2
EOF
simple_test

setup "up"

ok <<EOF
NOTICE: vsftpd listening on TCP port 21: no longer failing
EOF
simple_test
