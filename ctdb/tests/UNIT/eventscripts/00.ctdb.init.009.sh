#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "TDB check, bad TDB multiple times"

setup

db="${CTDB_DBDIR}/foo.tdb.0"
FAKE_TDB_IS_OK="no"

required_result_tdbcheck ()
{
	ok <<EOF
WARNING: database ${db} is corrupted.
 Moving to backup ${db}.DATE.TIME.corrupt for later analysis.
EOF
}

# List the corrupt databases
test_num_corrupt ()
{
	(cd "$CTDB_DBDIR" && ls foo.tdb.0.*.corrupt)
}

# Required result is a list of up to 10 corrupt databases
required_result_num_corrupt ()
{
	_num="$1"

	if [ "$_num" -gt 10 ] ; then
		_num=10
	fi

	_t=""
	for _x in $(seq 1 $_num) ; do
		_t="${_t:+${_t}
}foo.tdb.0.DATE.TIME.corrupt"
	done

	ok "$_t"
}

for i in $(seq 1 15) ; do
	FAKE_SLEEP_REALLY=yes sleep 1
	touch "$db"
	required_result_tdbcheck
	simple_test
	required_result_num_corrupt "$i"
	simple_test_command test_num_corrupt
done
