#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "managed"

setup_httpd "up"
export CTDB_MANAGES_HTTPD="yes"

ok <<EOF
Stopping httpd: OK
EOF
simple_test
