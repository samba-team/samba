#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "auto-stop, simple"

setup_samba

export CTDB_MANAGED_SERVICES="foo"
unset CTDB_MANAGES_SAMBA
unset CTDB_MANAGES_WINBIND

ok <<EOF
Stopping service "samba" - no longer managed
Stopping smb: OK
Stopping winbind: OK
EOF

simple_test
