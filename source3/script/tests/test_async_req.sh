#!/bin/sh

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

SOCKET_WRAPPER_IPV4_NETWORK="127.0.0.0"
export SOCKET_WRAPPER_IPV4_NETWORK

testit "async_connect_send" $VALGRIND $BINDIR/async_connect_send_test ||
	failed=`expr $failed + 1`

testok $0 $failed
