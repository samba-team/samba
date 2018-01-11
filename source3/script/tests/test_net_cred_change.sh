#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: test_net_cred_change.sh CONFIGURATION
EOF
exit 1;
fi

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh
testit "1: change machine secret" $VALGRIND $BINDIR/wbinfo --change-secret || failed=`expr $failed + 1`
testit "1: validate secret" $VALGRIND $BINDIR/net rpc testjoin $@ || failed=`expr $failed + 1`
testit "2: change machine secret" $VALGRIND $BINDIR/wbinfo --change-secret || failed=`expr $failed + 1`
testit "2: validate secret" $VALGRIND $BINDIR/net rpc testjoin $@ || failed=`expr $failed + 1`

testok $0 $failed
