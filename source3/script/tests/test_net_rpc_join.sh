#!/bin/sh

if [ $# -lt 4 ]; then
cat <<EOF
Usage: test_net_rpc_join.sh  USERNAME PASSWORD SERVER PREFIX
EOF
exit 1;
fi

USERNAME="$1"
PASSWORD="$2"
SERVER="$3"
PREFIX="$4"
shift 4
ADDARGS="$*"

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh
mkdir -p $PREFIX/private
testit "net_rpc_join" $VALGRIND $BINDIR/net rpc join -S $SERVER --option=netbiosname=netrpcjointest --option=domainlogons=yes --option=privatedir=$PREFIX/private -U$USERNAME%$PASSWORD $ADDARGS || failed=`expr $failed + 1`
testit "net_rpc_testjoin" $VALGRIND $BINDIR/net rpc testjoin -S $SERVER --option=netbiosname=netrpcjointest --option=domainlogons=yes --option=privatedir=$PREFIX/private $ADDARGS || failed=`expr $failed + 1`
testit "net_rpc_changetrustpw" $VALGRIND $BINDIR/net rpc changetrustpw -S $SERVER --option=netbiosname=netrpcjointest --option=domainlogons=yes --option=privatedir=$PREFIX/private $ADDARGS || failed=`expr $failed + 1`
testit "net_rpc_testjoin2" $VALGRIND $BINDIR/net rpc testjoin -S $SERVER --option=netbiosname=netrpcjointest --option=domainlogons=yes --option=privatedir=$PREFIX/private $ADDARGS || failed=`expr $failed + 1`

testok $0 $failed
