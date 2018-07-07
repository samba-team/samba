#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "managed, down - 5 times"

setup "down"

ok_null
simple_test

ok <<EOF
HTTPD is not running. Trying to restart HTTPD.
service: can't stop httpd - not running
Starting httpd: OK
EOF
simple_test

ok_null
simple_test

ok_null
simple_test

required_result 1 <<EOF
HTTPD is not running. Trying to restart HTTPD.
Stopping httpd: OK
Starting httpd: OK
EOF
simple_test
