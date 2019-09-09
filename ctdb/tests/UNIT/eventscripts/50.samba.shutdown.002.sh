#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "shutdown, simple"

setup

samba_setup_fake_threads 1 2 3 4 5 6

ok <<EOF
Stopping smb: OK
$SAMBA_STACK_TRACES
EOF
simple_test
