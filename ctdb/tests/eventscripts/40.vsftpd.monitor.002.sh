#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "managed, down - once, twice"

setup_vsftpd "down"
export CTDB_MANAGES_VSFTPD="yes"

ok <<EOF
ERROR: vsftpd tcp port 21 is not responding
WARNING: vsftpd not listening but less than 2 consecutive failures, not unhealthy yet
EOF
simple_test

required_result 1 <<EOF
ERROR: vsftpd tcp port 21 is not responding
ERROR: 2 consecutive failures for vsftpd, marking node unhealthy
EOF
simple_test
