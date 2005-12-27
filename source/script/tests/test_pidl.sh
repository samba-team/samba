#!/bin/sh
if [ ! -n "$PERL" ]
then
	PERL=perl
fi

incdir=`dirname $0`
. $incdir/test_functions.sh


for f in pidl/tests/*.pl; do
    testit "$f" $PERL -MExtUtils::Command::MM -e "test_harness()" $f || failed=`expr $failed + 1`
done

testok $0 $failed
