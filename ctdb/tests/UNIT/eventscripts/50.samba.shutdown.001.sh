#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "shutdown, simple"

setup

ok <<EOF
Stopping smb: OK
EOF
simple_test
