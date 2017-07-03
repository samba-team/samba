#!/bin/sh
#
# Test 'net cache samlogon' command.
#

if [ $# -lt 4 ]; then
cat <<EOF
Usage: $0 SERVER SHARE USER PASS
EOF
exit 1;
fi

SERVER=$1
SHARE=$2
USER=$3
PASS=$4
smbclient=$BINDIR/smbclient

failed=0

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh
. $incdir/common_test_fns.inc

# Ensure the samlogon cache is primed
test_smbclient "Prime samlogon cache" 'exit' //$SERVER/$SHARE -U$USER%$PASS || failed=$(expr $failed + 1)

# Ensure list works and remember the sid and name of the first entry
testit "net cache samlogon list" $BINDIR/net cache samlogon list || failed=$(expr $failed + 1)
usersid=$($BINDIR/net cache samlogon list | awk '/^S-/ { print $1 ; exit }')
username=$($BINDIR/net cache samlogon list | awk '/^S-/ { print $2 ; exit }')

# Test the show command with the sid from the previous list command
testit "net cache samlogon show $usersid" $BINDIR/net cache samlogon show $usersid || failed=$(expr $failed + 1)
tmp=$($BINDIR/net cache samlogon show $usersid | awk '/^Name:/ {print $2}')
testit "net cache samlogon show SID name matches name from list command" test x"$tmp" = x"$username" || failed=$(expr $failed + 1)

testit "net cache samlogon ndrdump $usersid" $BINDIR/net cache samlogon ndrdump $usersid || failed=$(expr $failed + 1)
tmp=$($BINDIR/net cache samlogon ndrdump $usersid | head -n 1 | grep "netr_SamInfo3: struct netr_SamInfo3")
retval=$?
testit "net cache samlogon ndrdump returns netr_SamInfo3 structure" test $retval -eq 0 || failed=$(expr $failed + 1)

testok $0 $failed
