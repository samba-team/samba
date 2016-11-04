#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "shutdown, Debian init style"

setup_samba

export EVENTSCRIPT_TESTS_INIT_STYLE="debian"

ok <<EOF
Stopping smbd: OK
Stopping nmbd: OK
EOF
simple_test
