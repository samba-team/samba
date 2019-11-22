#!/bin/sh

# various tests for the "net" command

if [ $# -lt 3 ]; then
cat <<EOF
Usage: test_net_misc.sh SCRIPTDIR SERVERCONFFILE NET CONFIGURATION
EOF
exit 1;
fi

SCRIPTDIR="$1"
SERVERCONFFILE="$2"
NET="$3"
CONFIGURATION="$4"

# optional protocl, default to NT1
if [ $# -gt 4 ]; then
	PROTOCOL="$5"
else
	PROTOCOL="NT1"
fi

NET="$VALGRIND ${NET:-$BINDIR/net} $CONFIGURATION"
NETTIME="${NET}   --option=clientmaxprotocol=${PROTOCOL} time"
NETLOOKUP="${NET} --option=clientmaxprotocol=${PROTOCOL} lookup"
NETSHARE="${NET} -U${USERNAME}%${PASSWORD} --option=clientmaxprotocol=${PROTOCOL} -S ${SERVER} share"

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

test_time()
{
	PARAM="$1"

	${NETTIME} -S ${SERVER} ${PARAM}
}

test_lookup()
{
	PARAM="$1"

	${NETLOOKUP} ${PARAM}
}

test_share()
{
	PARAM="$1"

	${NETSHARE} ${PARAM}
}

testit "get the time" \
	test_time || \
	failed=`expr $failed + 1`

testit "get the system time" \
	test_time system || \
	failed=`expr $failed + 1`

testit "get the time zone" \
	test_time zone || \
	failed=`expr $failed + 1`

testit "lookup the PDC" \
	test_lookup pdc || \
	failed=`expr $failed + 1`

testit "lookup the master browser" \
	test_lookup master || \
	failed=`expr $failed + 1`

# This test attempts to lookup shares
testit "lookup share list" \
	test_share list || \
	failed=`expr $failed + 1`

testok $0 $failed

