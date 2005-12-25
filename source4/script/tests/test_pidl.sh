#!/bin/sh
if [ ! -n "$PERL" ]
then
	PERL=perl
fi

incdir=`dirname $0`
. $incdir/test_functions.sh

$PERL -MExtUtils::Command::MM -e "test_harness()" pidl/tests/*.pl || testok $0 1
