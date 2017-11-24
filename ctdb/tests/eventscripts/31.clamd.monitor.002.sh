#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Managed, clamd not listening"

export CTDB_MANAGES_CLAMD=yes
export CTDB_CLAMD_SOCKET="/var/run/clamd.sock"

setup_generic

required_result 1 <<EOF
ERROR: clamd not listening on $CTDB_CLAMD_SOCKET
EOF
simple_test
