#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Managed, clamd not listening"

setup

CTDB_MANAGES_CLAMD=yes
CTDB_CLAMD_SOCKET="/var/run/clamd.sock"

required_result 1 <<EOF
ERROR: clamd not listening on $CTDB_CLAMD_SOCKET
EOF
simple_test
