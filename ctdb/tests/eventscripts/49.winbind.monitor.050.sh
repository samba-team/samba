#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "auto-start, simple"

setup_winbind "down"

export CTDB_SERVICE_AUTOSTARTSTOP="yes"
export CTDB_MANAGED_SERVICES="foo winbind bar"

ok <<EOF
Starting service "winbind" - now managed
&Starting winbind: OK
EOF
simple_test
