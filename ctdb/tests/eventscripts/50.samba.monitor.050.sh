#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "auto-start, simple"

setup_samba "down"

export CTDB_SERVICE_AUTOSTARTSTOP="yes"
export CTDB_MANAGED_SERVICES="foo samba winbind bar"

ok <<EOF
Starting service "samba" - now managed
&Starting smb: OK
EOF
simple_test
