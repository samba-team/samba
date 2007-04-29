#!/bin/sh
# run a quick set of filesystem tests

ADDARGS="$*"

incdir=`dirname $0`
. $incdir/test_functions.sh

tests="BASE-RW1"

for t in $tests; do
    name="$t"
    plantest "$name" dc $VALGRIND bin/smbtorture $TORTURE_OPTIONS $ADDARGS //\$SERVER/simple -U"\$USERNAME"%"\$PASSWORD" $t
done
