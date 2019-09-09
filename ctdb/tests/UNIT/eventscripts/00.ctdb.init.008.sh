#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "TDB check, tdbtool supports check, bad persistent TDB"

setup

FAKE_TDBTOOL_SUPPORTS_CHECK="yes"

db="${CTDB_DBDIR_PERSISTENT}/foo.tdb.0"
touch "$db"
FAKE_TDB_IS_OK="no"

required_result 1 <<EOF
Persistent database ${db} is corrupted! CTDB will not start.
EOF

simple_test
