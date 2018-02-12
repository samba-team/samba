#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "managed"

setup "down"

CTDB_MANAGES_HTTPD="yes"

ok <<EOF
Starting httpd: OK
EOF
simple_test
