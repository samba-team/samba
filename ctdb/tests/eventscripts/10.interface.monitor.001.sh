#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "no public addresses"

setup_ctdb

rm -f "${CTDB_BASE}/public_addresses"

ok_null

simple_test
