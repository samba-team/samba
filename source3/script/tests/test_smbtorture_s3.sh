#!/bin/sh

# this runs the file serving tests that are expected to pass with samba3

if [ $# -lt 5 ]; then
cat <<EOF
Usage: test_smbtorture_s3.sh TEST UNC USERNAME PASSWORD SMBTORTURE <smbtorture args>
EOF
exit 1;
fi

t="$1"
unc="$2"
username="$3"
password="$4"
SMBTORTURE="$5"
shift 5
ADDARGS="$*"

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh



failed=0
testit "smbtorture" $VALGRIND $SMBTORTURE $unc -U"$username"%"$password" $ADDARGS $t || failed=`expr $failed + 1`

testok $0 $failed
