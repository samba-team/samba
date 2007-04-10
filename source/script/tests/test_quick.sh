#!/bin/sh
# run a quick set of filesystem tests

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
    name="$t"
    plantest "$name" base $VALGRIND bin/smbtorture $TORTURE_OPTIONS $ADDARGS //\$SERVER/cifs -U"\$USERNAME"%"\$PASSWORD" $t
done
