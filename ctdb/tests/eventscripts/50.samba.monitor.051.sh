#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "auto-stop, simple"

setup_samba

export CTDB_SERVICE_AUTOSTARTSTOP="yes"
export CTDB_MANAGED_SERVICES="foo"
unset CTDB_MANAGES_SAMBA

ok <<EOF
Stopping service "samba" - no longer managed
&Stopping smb: OK
EOF
simple_test
