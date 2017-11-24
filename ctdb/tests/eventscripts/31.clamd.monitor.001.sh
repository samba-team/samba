#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Not managed, clamd not listening"

export CTDB_MANAGES_CLAMD=no
export CTDB_CLAMD_SOCKET="/var/run/clamd.sock"

setup_generic

ok_null
simple_test
