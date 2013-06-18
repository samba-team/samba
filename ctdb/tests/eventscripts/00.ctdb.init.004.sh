#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "TDB check, tdbtool supports check, bad TDB"

setup_ctdb

FAKE_TDBTOOL_SUPPORTS_CHECK="yes"

db="${CTDB_DBDIR}/foo.tdb.0"
touch "$db"
FAKE_TDB_IS_OK="no"

FAKE_DATE_OUTPUT="19690818.103000.000000001"

ok <<EOF
WARNING: database ${db} is corrupted.
 Moving to backup ${db}.${FAKE_DATE_OUTPUT}.corrupt for later analysis.
EOF

simple_test
