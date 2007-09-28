#!/bin/sh

# this runs the file serving tests that are expected to pass with samba3

ADDARGS="$*"

incdir=`dirname $0`
. $incdir/test_functions.sh

BINDIR=$incdir/../../bin

tests="FDPASS LOCK1 LOCK2 LOCK3 LOCK4 LOCK5 LOCK6 LOCK7"
tests="$tests UNLINK BROWSE ATTR TRANS2 MAXFID TORTURE "
tests="$tests OPLOCK1 OPLOCK2 OPLOCK3"
tests="$tests DIR DIR1 TCON TCONDEV RW1 RW2 RW3"
tests="$tests OPEN XCOPY RENAME DELETE PROPERTIES W2K"
tests="$tests TCON2 IOCTL CHKPATH FDSESS LOCAL-SUBSTITUTE"

for t in $tests; do
    plantest "SAMBA3-$t" dc $VALGRIND $BINDIR/smbtorture $ADDARGS //\$SERVER_IP/tmp -U"\$USERNAME"%"\$PASSWORD" $t
done
