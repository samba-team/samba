#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Managed, clamd listening"

setup

CTDB_MANAGES_CLAMD=yes
CTDB_CLAMD_SOCKET="/var/run/clamd.sock"

unix_socket_listening "$CTDB_CLAMD_SOCKET"

ok_null
simple_test
