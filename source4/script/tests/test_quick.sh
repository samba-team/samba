#!/bin/sh
# run a quick set of filesystem tests

if [ $# -lt 3 ]; then
cat <<EOF
Usage: test_quick.sh UNC USERNAME PASSWORD <first> <smbtorture args>
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

tests="BASE-UNLINK BASE-ATTR BASE-DELETE"
tests="$tests BASE-TCON BASE-OPEN"
tests="$tests BASE-CHKPATH RAW-QFSINFO RAW-QFILEINFO RAW-SFILEINFO"
tests="$tests RAW-MKDIR RAW-SEEK RAW-OPEN RAW-WRITE"
tests="$tests RAW-UNLINK RAW-READ RAW-CLOSE RAW-IOCTL RAW-RENAME"
tests="$tests RAW-EAS RAW-STREAMS"

for t in $tests; do
    if [ ! -z "$start" -a "$start" != $t ]; then
	continue;
    fi
    start=""
    name="$t"
    plantest "$name" base $VALGRIND bin/smbtorture $TORTURE_OPTIONS $ADDARGS $unc -U"$username"%"$password" $t
done
