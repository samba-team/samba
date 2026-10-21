#!/bin/sh
#
# dbwrap_parse_record_send() on ctdb for a record whose dmaster is
# another node: dbwrap_tool runs against node 0, the record is written
# on node 1.
#

if [ $# -lt 2 ]; then
	cat <<EOF
Usage: test_dbwrap_ctdb_parse_record_send.sh CTDB_PREFIX DBWRAP_TOOL
EOF
	exit 1
fi

CTDB_PREFIX="$1"
DBWRAP_TOOL="$2"
shift 2

incdir="$(dirname "$0")/../../../testprogs/blackbox"
. "${incdir}/subunit.sh"

failed=0

db="torture_parse_record_send.tdb"
key="parse_send_key"

ctdb_onnode()
{
	pnn="$1"
	shift
	(
		# The testenv has CTDB_SOCKET and CTDB_BASE pointing to
		# the first node, local_daemons.sh doesn't want them
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

parse_record_send()
{
	hex="$1"
	out="$($VALGRIND "${DBWRAP_TOOL}" --non-persistent "${db}" parse_records "${key}")" || return 1
	test "${out}" = "0: ${key}: ${hex}"
}

testit "attach ${db}" \
	ctdb_onnode all attach "${db}" ||
	failed=$((failed + 1))

#
# Node 0 asks ctdbd for the record, the parser must see the value
# written on node 1
#
testit "store value1 on node 1" \
	dbwrap_tool_onnode 1 store "${key}" string value1 ||
	failed=$((failed + 1))

testit "parse_record_send value1 on node 0" \
	parse_record_send 76616C75653100 ||
	failed=$((failed + 1))

#
# Node 1 writes again, node 0 keeps a copy it can't use anymore and
# must ask ctdbd again
#
testit "store value2 on node 1" \
	dbwrap_tool_onnode 1 store "${key}" string value2 ||
	failed=$((failed + 1))

testit "parse_record_send value2 on node 0" \
	parse_record_send 76616C75653200 ||
	failed=$((failed + 1))

testok "$0" "${failed}"
