#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "managed"

setup_httpd "down"
export CTDB_MANAGES_HTTPD="yes"

ok <<EOF
Starting httpd: OK
EOF
simple_test
