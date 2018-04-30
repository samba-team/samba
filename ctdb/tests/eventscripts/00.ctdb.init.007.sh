#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "TDB check, tdbtool supports check, good persistent TDB"

setup

FAKE_TDBTOOL_SUPPORTS_CHECK="yes"

touch "${CTDB_DBDIR_PERSISTENT}/foo.tdb.0"
FAKE_TDB_IS_OK="yes"

ok_null

simple_test
