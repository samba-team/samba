#!/bin/sh

# this runs the file serving tests that are expected to pass with samba3 against shares with various options

if [ $# -lt 4 ]; then
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

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

testit "smbclient //$SERVER/guestonly" $SMBCLIENT //$SERVER/guestonly $CONFIGURATION -U$USERNAME%$PASSWORD -I $SERVER_IP -p 139 -c quit $ADDARGS
testit "smbclient //$SERVER/guestonly as anon" $SMBCLIENT //$SERVER/guestonly $CONFIGURATION -U% -I $SERVER_IP -p 139 -c quit $ADDARGS
testit "smbclient //$SERVER/tmpguest" $SMBCLIENT //$SERVER/tmpguest $CONFIGURATION -U$USERNAME%$PASSWORD -I $SERVER_IP -p 139 -c quit $ADDARGS
testit "smbclient //$SERVER/tmpguest as anon" $SMBCLIENT //$SERVER/tmpguest $CONFIGURATION -U% -I $SERVER_IP -p 139 -c quit $ADDARGS
testit "smbclient //$SERVER/forceuser" $SMBCLIENT //$SERVER/forceuser $CONFIGURATION -U$USERNAME%$PASSWORD -I $SERVER_IP -p 139 -c quit $ADDARGS
testit "smbclient //$SERVER/forceuser as anon" $SMBCLIENT //$SERVER/forceuser $CONFIGURATION -U% -I $SERVER_IP -p 139 -c quit $ADDARGS
testit "smbclient //$SERVER/forceuser_unixonly" $SMBCLIENT //$SERVER/forceuser_unixonly $CONFIGURATION -U$USERNAME%$PASSWORD -I $SERVER_IP -p 139 -c quit $ADDARGS
testit "smbclient //$SERVER/forcegroup" $SMBCLIENT //$SERVER/forcegroup $CONFIGURATION -U$USERNAME%$PASSWORD -I $SERVER_IP -p 139 -c quit $ADDARGS
testit "smbclient //$SERVER/forcegroup as anon" $SMBCLIENT //$SERVER/forcegroup $CONFIGURATION -U% -I $SERVER_IP -p 139 -c quit $ADDARGS
