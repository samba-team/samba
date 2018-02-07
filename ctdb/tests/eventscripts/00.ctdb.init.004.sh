#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "TDB check, tdbtool supports check, bad TDB"

setup

db="${CTDB_DBDIR}/foo.tdb.0"
touch "$db"
FAKE_TDB_IS_OK="no"

ok <<EOF
WARNING: database ${db} is corrupted.
 Moving to backup ${db}.DATE.TIME.corrupt for later analysis.
EOF

simple_test
