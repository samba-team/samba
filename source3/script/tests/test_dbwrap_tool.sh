#!/bin/sh
#
# Test dbwrap_tool parse_records with multiple keys
#

if [ $# -lt 2 ]; then
	cat <<EOF
Usage: test_dbwrap_tool.sh CTDB_PREFIX DBWRAP_TOOL
EOF
	exit 1
fi

CTDB_PREFIX="$1"
DBWRAP_TOOL="$2"
shift 2

incdir="$(dirname "$0")/../../../testprogs/blackbox"
. "${incdir}/subunit.sh"

failed=0

db="test_dbwrap_tool.tdb"

ctdb_onnode()
{
	pnn="$1"
	shift
	(
		unset CTDB_SOCKET CTDB_BASE
		./ctdb/tests/local_daemons.sh "${CTDB_PREFIX}" \
			onnode "${pnn}" "ctdb $*"
	)
}

#
# Run dbwrap_tool against the given node's ctdbd
#
dbwrap_tool_onnode()
{
	pnn="$1"
	shift
	$VALGRIND "${DBWRAP_TOOL}" \
		--configfile="${CTDB_PREFIX}/node.${pnn}/lib/server.conf" \
		--non-persistent "${db}" "$@"
}

testit "attach ${db}" \
	ctdb_onnode all attach "${db}" ||
	failed=$((failed + 1))

testit "store key1 on node 0" \
	dbwrap_tool_onnode 0 store key1 string val1 ||
	failed=$((failed + 1))

testit "store key2 on node 1" \
	dbwrap_tool_onnode 1 store key2 string val2 ||
	failed=$((failed + 1))

testit "store key3 on node 2" \
	dbwrap_tool_onnode 2 store key3 string val3 ||
	failed=$((failed + 1))

test_parse_records_3()
{
	out="$($VALGRIND "${DBWRAP_TOOL}" --non-persistent "${db}" parse_records key1 key2 key3)" || return 1

	# The records arrive in any order
	out="$(printf '%s\n' "${out}" | sort)"
	expected=$(printf "0: key1: 76616C3100\n1: key2: 76616C3200\n2: key3: 76616C3300\n")
	test "${out}" = "${expected}"
}

testit "parse_records 3 keys" \
	test_parse_records_3 ||
	failed=$((failed + 1))

#
# A missing key must fail the command, but the other keys must still
# be printed
#
test_parse_records_missing()
{
	out="$($VALGRIND "${DBWRAP_TOOL}" --non-persistent "${db}" parse_records key1 nokey 2>&1)" && return 1
	echo "${out}"
	echo "${out}" | grep -q "^0: key1: 76616C3100$" || return 1
	echo "${out}" | grep -q "parse_record failed for 'nokey': NT_STATUS_NOT_FOUND"
}

testit "parse_records missing key" \
	test_parse_records_missing ||
	failed=$((failed + 1))

testok "$0" "${failed}"
