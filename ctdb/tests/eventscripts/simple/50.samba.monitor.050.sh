#!/bin/sh

. "${EVENTSCRIPTS_TESTS_DIR}/common.sh"

define_test "auto-start, simple"

setup_samba "down"

export CTDB_MANAGED_SERVICES="foo samba winbind bar"

ok <<EOF
Starting service "samba" - now managed
Starting winbind: OK
Starting smb: OK
EOF

simple_test
