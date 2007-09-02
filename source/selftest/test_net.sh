#!/bin/sh

# add tests to this list as they start passing, so we test
# that they stay passing
incdir=`dirname $0`
. $incdir/test_functions.sh

tests=`$samba4bindir/smbtorture --list | grep ^NET-`

for t in $tests; do
    plantest "$t" dc $VALGRIND $samba4bindir/smbtorture $TORTURE_OPTIONS "\$SERVER[$VALIDATE]" -U"\$USERNAME"%"\$PASSWORD" -W "\$DOMAIN" $t "$*"
done
