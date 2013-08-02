#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "auto-stop, simple"

setup_winbind

export CTDB_SERVICE_AUTOSTARTSTOP="yes"
export CTDB_MANAGED_SERVICES="foo"
unset CTDB_MANAGES_WINBIND

ok <<EOF
Stopping service "winbind" - no longer managed
&Stopping winbind: OK
EOF
simple_test
