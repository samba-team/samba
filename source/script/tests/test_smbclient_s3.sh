#!/bin/sh

# this runs the file serving tests that are expected to pass with samba3

if [ $# != 2 ]; then
cat <<EOF
Usage: test_smbclient_s3.sh SERVER SERVER_IP
EOF
exit 1;
fi

SERVER="$1"
SERVER_IP="$2"

incdir=`dirname $0`
. $incdir/test_functions.sh

failed=0

testit "smbclient -L $SERVER_IP" $VALGRIND $SRCDIR/bin/smbclient $CONFIGURATION -L $SERVER_IP -N -p 139 || failed=`expr $failed + 1`
testit "smbclient -L $SERVER" $VALGRIND $SRCDIR/bin/smbclient $CONFIGURATION -L $SERVER -N -p 139 || failed=`expr $failed + 1`

testok $0 $failed
