#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "shutdown, Debian init style"

setup_samba

export EVENTSCRIPT_TESTS_INIT_STYLE="debian"

ok <<EOF
Starting nmbd: OK
Starting smbd: OK
EOF
simple_test
