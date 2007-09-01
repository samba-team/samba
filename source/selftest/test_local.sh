#!/bin/sh

incdir=`dirname $0`
. $incdir/test_functions.sh

for t in `$samba4bindir/smbtorture --list | grep "^LOCAL-" | xargs`; do
	plantest "$t" none $VALGRIND $samba4bindir/smbtorture $TORTURE_OPTIONS ncalrpc: $t "$*"
done

plantest "tdb stress" none $VALGRIND $samba4bindir/tdbtorture
