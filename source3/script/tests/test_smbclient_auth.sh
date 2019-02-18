#!/bin/sh

# this runs the file serving tests that are expected to pass with samba3 against shares with various options

if [ $# -lt 5 ]; then
cat <<EOF
Usage: test_smbclient_auth.sh SERVER SERVER_IP USERNAME PASSWORD SMBCLIENT <smbclient arguments>
EOF
exit 1;
fi

SERVER="$1"
SERVER_IP="$2"
USERNAME="$3"
PASSWORD="$4"
SMBCLIENT="$5"
SMBCLIENT="$VALGRIND ${SMBCLIENT}"
shift 5
ADDARGS="$*"

failed=0

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

echo "${SERVER_IP}" | grep -q ':.*:' && {
	# If we have an ipv6 address e.g.
	# fd00:0000:0000:0000:0000:0000:5357:5f03
	# we also try
	# fd00-0000-0000-0000-0000-0000-5357-5f03.ipv6-literal.net
	IPV6LITERAL=$(echo "${SERVER_IP}.ipv6-literal.net" | sed -e 's!:!-!g' -e 's!%!s!')
	testit "smbclient //${IPV6LITERAL}/tmpguest as user" $SMBCLIENT //${IPV6LITERAL}/tmpguest $CONFIGURATION -U$USERNAME%$PASSWORD -c quit $ADDARGS || failed=`expr $failed + 1`
	testit "smbclient //${IPV6LITERAL}./tmpguest as user" $SMBCLIENT //${IPV6LITERAL}./tmpguest $CONFIGURATION -U$USERNAME%$PASSWORD -c quit $ADDARGS || failed=`expr $failed + 1`
}
testit "smbclient //${SERVER_IP}/tmpguest as user" $SMBCLIENT //${SERVER_IP}/tmpguest $CONFIGURATION -U$USERNAME%$PASSWORD -p 139 -c quit $ADDARGS || failed=`expr $failed + 1`

testit "smbclient //$SERVER/guestonly as user" $SMBCLIENT //$SERVER/guestonly $CONFIGURATION -U$USERNAME%$PASSWORD -I $SERVER_IP -p 139 -c quit $ADDARGS || failed=`expr $failed + 1`
testit "smbclient //$SERVER/guestonly as anon" $SMBCLIENT //$SERVER/guestonly $CONFIGURATION -U% -I $SERVER_IP -p 139 -c quit $ADDARGS || failed=`expr $failed + 1`
testit "smbclient //$SERVER/tmpguest as user" $SMBCLIENT //$SERVER/tmpguest $CONFIGURATION -U$USERNAME%$PASSWORD -I $SERVER_IP -p 139 -c quit $ADDARGS || failed=`expr $failed + 1`
testit "smbclient //$SERVER/tmpguest as anon" $SMBCLIENT //$SERVER/tmpguest $CONFIGURATION -U% -I $SERVER_IP -p 139 -c quit $ADDARGS || failed=`expr $failed + 1`
testit "smbclient //$SERVER/forceuser as user" $SMBCLIENT //$SERVER/forceuser $CONFIGURATION -U$USERNAME%$PASSWORD -I $SERVER_IP -p 139 -c quit $ADDARGS || failed=`expr $failed + 1`
testit "smbclient //$SERVER/forceuser as anon" $SMBCLIENT //$SERVER/forceuser $CONFIGURATION -U% -I $SERVER_IP -p 139 -c quit $ADDARGS || failed=`expr $failed + 1`
testit "smbclient //$SERVER/forceuser_unixonly as user" $SMBCLIENT //$SERVER/forceuser_unixonly $CONFIGURATION -U$USERNAME%$PASSWORD -I $SERVER_IP -p 139 -c quit $ADDARGS || failed=`expr $failed + 1`
testit "smbclient //$SERVER/forceuser_wkngroup as user" $SMBCLIENT //$SERVER/forceuser_wkngroup $CONFIGURATION -U$USERNAME%$PASSWORD -I $SERVER_IP -p 139 -c quit $ADDARGS || failed=`expr $failed + 1`
testit "smbclient //$SERVER/forcegroup as user" $SMBCLIENT //$SERVER/forcegroup $CONFIGURATION -U$USERNAME%$PASSWORD -I $SERVER_IP -p 139 -c quit $ADDARGS || failed=`expr $failed + 1`
testit "smbclient //$SERVER/forcegroup as anon" $SMBCLIENT //$SERVER/forcegroup $CONFIGURATION -U% -I $SERVER_IP -p 139 -c quit $ADDARGS || failed=`expr $failed + 1`
exit $failed
