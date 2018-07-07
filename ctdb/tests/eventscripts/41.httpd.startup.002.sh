#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "managed"

setup "down"

ok <<EOF
Starting httpd: OK
EOF
simple_test
