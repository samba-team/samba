#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "TDB check, tdbtool does not support check, good TDB"

setup

FAKE_TDBTOOL_SUPPORTS_CHECK="no"

touch "${CTDB_DBDIR}/foo.tdb.0"
FAKE_TDB_IS_OK="yes"

ok <<EOF
WARNING: The installed 'tdbtool' does not offer the 'check' subcommand.
 Using 'tdbdump' for database checks.
 Consider updating 'tdbtool' for better checks!
EOF

simple_test
