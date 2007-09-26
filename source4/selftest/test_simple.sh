#!/bin/sh
# run a quick set of filesystem tests

ADDARGS="$*"

incdir=`dirname $0`
. $incdir/test_functions.sh

tests="BASE-RW1"

for t in $tests; do
    plantest "ntvfs/simple $t" dc $VALGRIND $samba4bindir/smbtorture $TORTURE_OPTIONS $ADDARGS //\$SERVER/simple -U"\$USERNAME"%"\$PASSWORD" $t
done
