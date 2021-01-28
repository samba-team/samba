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
#
# Subtle extra test for bug https://bugzilla.samba.org/show_bug.cgi?id=13992
#
# '^ user1$' must appear MORE THAN ONCE, as it can read more than one
# share. The previous test found user1, but only once as the bug only
# allows reading the security descriptor for one share, and we were
# unlucky that the first share security descriptor returned allows
# user1 to read from it.
#
subunit_start_test "net_rpc_share_allowedusers"
multi_userout=`$net usersidlist | $VALGRIND $net rpc share allowedusers -S$SERVER -U$USERNAME%$PASSWORD $ADDARGS`
num_matches=`echo "$multi_userout" | grep -c '^ user1$'`
if [ "$num_matches" -gt "1" ]
then
	subunit_pass_test "net_rpc_share_allowedusers"
else
	echo "net_rpc_share_allowedusers only found $num_matches shares readable by user1. Should be greater than one.\n"
	failed=`expr $failed + 1`
	echo "$multi_userout" | subunit_fail_test "net_rpc_share_allowedusers"
fi

testok $0 $failed
