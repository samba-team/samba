#!/bin/sh
# run a quick set of filesystem tests

if [ $# -lt 3 ]; then
cat <<EOF
Usage: test_simple.sh UNC USERNAME PASSWORD <first> <smbtorture args>
EOF
exit 1;
fi

unc="$1"
username="$2"
password="$3"
start="$4"
shift 4
ADDARGS="$*"

incdir=`dirname $0`
. $incdir/test_functions.sh

tests="BASE-RW1"

failed=0
for t in $tests; do
    if [ ! -z "$start" -a "$start" != $t ]; then
	continue;
    fi
    start=""
    name="$t"
    testit "$name" smb $VALGRIND bin/smbtorture $TORTURE_OPTIONS $ADDARGS $unc -U"$username"%"$password" $t
done

testok $0 $failed

