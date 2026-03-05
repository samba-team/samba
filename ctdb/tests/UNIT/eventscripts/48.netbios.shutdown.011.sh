#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "shutdown, Debian init style"

setup

export EVENTSCRIPT_TESTS_PLATFORM_STYLE="debian"

ok <<EOF
Stopping nmbd: OK
EOF
simple_test
