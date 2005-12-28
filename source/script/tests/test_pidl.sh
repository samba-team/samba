#!/bin/sh
if [ ! -n "$PERL" ]
then
	PERL=perl
fi

incdir=`dirname $0`
. $incdir/test_functions.sh

failed=0

for f in pidl/tests/*.pl; do
    testit "$f" $PERL $f || failed=`expr $failed + 1`
done

testok $0 $failed
