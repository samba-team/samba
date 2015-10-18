#!/bin/sh

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

testit "async_connect_send" $VALGRIND $BINDIR/async_connect_send_test ||
	failed=`expr $failed + 1`

testok $0 $failed
