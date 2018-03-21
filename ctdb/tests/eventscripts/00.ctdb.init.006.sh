#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "TDB check, tdbtool does not support check, bad TDB"

setup_ctdb

FAKE_TDBTOOL_SUPPORTS_CHECK="no"

result_filter ()
{
	_date="[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]"
	_time="[0-9][0-9][0-9][0-9][0-9][0-9]"
	_nanos="[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]"
	_date_time="${_date}\.${_time}\.${_nanos}"
	sed -e "s|\.${_date_time}\.|.DATE.TIME.|"
}

db="${CTDB_DBDIR}/foo.tdb.0"
touch "$db"
FAKE_TDB_IS_OK="no"

ok <<EOF
WARNING: The installed 'tdbtool' does not offer the 'check' subcommand.
 Using 'tdbdump' for database checks.
 Consider updating 'tdbtool' for better checks!
WARNING: database ${db} is corrupted.
 Moving to backup ${db}.DATE.TIME.corrupt for later analysis.
EOF

simple_test
