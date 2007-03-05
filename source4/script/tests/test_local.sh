#!/bin/sh

local_tests=`bin/smbtorture --list | grep "^LOCAL-" | xargs`

if [ `uname` = "Linux" ]; then
    # testing against the system iconv only makes sense for our 'reference' iconv
    # behaviour
    local_tests="$local_tests LOCAL-ICONV"
fi

if [ $# -lt 0 ]; then
cat <<EOF
Usage: test_local.sh
EOF
exit 1;
fi

incdir=`dirname $0`
. $incdir/test_functions.sh

# the local tests don't need smbd
SMBD_TEST_FIFO=""
export SMBD_TEST_FIFO

failed=0
for t in $local_tests; do
	testit "$t" $VALGRIND bin/smbtorture $TORTURE_OPTIONS ncalrpc: $t "$*"
done

testit "tdb stress" $VALGRIND bin/tdbtorture

testok $0 $failed
