#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Managed, clamd listening"

export CTDB_MANAGES_CLAMD=yes
export CTDB_CLAMD_SOCKET="/var/run/clamd.sock"

setup_generic

unix_socket_listening "$CTDB_CLAMD_SOCKET"

ok_null
simple_test
