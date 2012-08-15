#!/bin/sh
if [ $# -lt 2 ]; then
cat <<EOF
Usage: run.sh VFSTEST PREFIX
EOF
exit 1;
fi

TESTBASE=`dirname $0`
VFSTEST=$1
PREFIX=$2
shift 2
ADDARGS="$*"

VFSTEST_PREFIX=vfstest
VFSTEST_TMPDIR=$(mktemp -d ${PREFIX}/${VFSTEST_PREFIX}_XXXXXX)

incdir=`dirname $0`/../../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

cd $VFSTEST_TMPDIR || exit 1

testit "vfstest" $VFSTEST -f $TESTBASE/vfstest.cmd $ADDARGS || failed=`expr $failed + 1`
testname=".streams check"
subunit_start_test $testname
NUM=`find .streams | wc -l`
if [ $NUM -ne 3 ] ; then
echo "streams_depot left ${NUM} in .streams, expected 3" | subunit_fail_test $testname
    failed=`expr $failed + 1`
else 
    subunit_pass_test $testname
fi

exit $failed
