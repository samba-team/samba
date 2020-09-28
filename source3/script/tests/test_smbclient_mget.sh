#!/bin/sh

if [ $# -lt 6 ]; then
cat <<EOF
Usage: $0 smbclient3 server share user password directory
EOF
exit 1;
fi

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

SMBCLIENT3="$1"; shift
SERVER="$1"; shift
SHARE="$1"; shift
USERNAME="$1"; shift
PASSWORD="$1"; shift
DIRECTORY="$1"; shift

# Can't use "testit" here -- it somehow breaks the -c command passed
# to smbclient into two, spoiling the "mget"

name="smbclient mget"
subunit_start_test "$name"
output=$("$SMBCLIENT3" //"$SERVER"/"$SHARE" \
         -U"$USERNAME"%"$PASSWORD" -c "recurse;prompt;mget $DIRECTORY")
status=$?
if [ x$status = x0 ]; then
    subunit_pass_test "$name"
else
    echo "$output" | subunit_fail_test "$name"
fi

testit "rm foo" rm "$DIRECTORY"/foo || failed=`expr $failed + 1`
testit "rmdir $DIRECTORY" rmdir "$DIRECTORY" || failed=`expr $failed + 1`

testok $0 $failed
