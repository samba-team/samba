#!/bin/sh

WBINFO="$VALGRIND ${WBINFO:-$BINDIR/wbinfo} $CONFIGURATION"
NET="$VALGRIND ${NET:-$BINDIR/net} $CONFIGURATION"
TEST_INT=`dirname $0`/test_wbinfo_sids2xids_int.py

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

testit "sids2xids" ${TEST_INT} ${WBINFO} ${NET} || failed=`expr $failed + 1`

testok $0 $failed
