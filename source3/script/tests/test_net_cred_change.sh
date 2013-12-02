#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: test_net_cred_change.sh CONFIGURATION
EOF
exit 1;
fi

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh
testit "first change" $VALGRIND $BINDIR/wbinfo -c || failed =`expr $failed + 1`
testit "first join" $VALGRIND $BINDIR/net rpc testjoin $@ || failed =`expr $failed + 1`
testit "second change" $VALGRIND $BINDIR/wbinfo -c || failed =`expr $failed + 1`

testok $0 $failed
