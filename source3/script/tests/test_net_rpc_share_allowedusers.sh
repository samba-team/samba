#!/bin/sh

if [ $# -lt 4 ]; then
cat <<EOF
Usage: test_net_rpc_share_allowedusers.sh  SERVER USERNAME PASSWORD PREFIX
EOF
exit 1;
fi

SERVER="$1"
USERNAME="$2"
PASSWORD="$3"
PREFIX="$4"
shift 4
ADDARGS="$*"

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh
mkdir -p $PREFIX/private
net=$BINDIR/net
# Check for the SID for group "Everyone" as a basic test things are working.
testit_grep "net_usersidlist" '^ S-1-1-0$' $VALGRIND $net usersidlist $ADDARGS || failed=`expr $failed + 1`
# Check "print$" share is listed by default.
testit_grep "net_rpc_share_allowedusers" '^print\$$' $net usersidlist | $VALGRIND $net rpc share allowedusers -S$SERVER -U$USERNAME%$PASSWORD $ADDARGS || failed=`expr $failed + 1`
# Check "print$" share is listed if we ask for it.
testit_grep "net_rpc_share_allowedusers" '^print\$$' $net usersidlist | $VALGRIND $net rpc share allowedusers -S$SERVER -U$USERNAME%$PASSWORD $ADDARGS - 'print$' || failed=`expr $failed + 1`
# Check user "user1" is allowed to read share "tmp".
testit_grep "net_rpc_share_allowedusers" '^ user1$' $net usersidlist | $VALGRIND $net rpc share allowedusers -S$SERVER -U$USERNAME%$PASSWORD $ADDARGS || failed=`expr $failed + 1`

testok $0 $failed
