#!/bin/sh

local_tests=`bin/smbtorture --list | grep "^LOCAL-" | xargs`

incdir=`dirname $0`
. $incdir/test_functions.sh

# the local tests don't need smbd
SMBD_TEST_FIFO=""
export SMBD_TEST_FIFO

for t in $local_tests; do
	plantest "$t" none $VALGRIND bin/smbtorture $TORTURE_OPTIONS ncalrpc: $t "$*"
done

plantest "tdb stress" none $VALGRIND bin/tdbtorture
