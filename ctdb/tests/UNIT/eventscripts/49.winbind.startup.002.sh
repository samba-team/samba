#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "managed"

setup "down"

ok <<EOF
Starting winbind: OK
EOF
simple_test
