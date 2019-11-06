#!/bin/sh

# this runs the file serving tests that are expected to pass with samba3 against shares with various options

if [ $# -lt 2 ]; then
cat <<EOF
Usage: test_smbclient_machine_auth.sh SERVER SMBCLIENT <smbclient arguments>
EOF
exit 1;
fi

SERVER="$1"
SMBCLIENT="$2"
SMBCLIENT="$VALGRIND ${SMBCLIENT}"
shift 2
ADDARGS="$*"

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

testit "smbclient //$SERVER/tmp" $SMBCLIENT //$SERVER/tmp --machine-pass -p 139 -c quit $ADDARGS

# Testing these here helps because we know the machine account isn't already this user/group
testit "smbclient //$SERVER/forceuser" $SMBCLIENT //$SERVER/tmp --machine-pass -p 139 -c quit $ADDARGS
testit "smbclient //$SERVER/forcegroup" $SMBCLIENT //$SERVER/tmp --machine-pass -p 139 -c quit $ADDARGS
