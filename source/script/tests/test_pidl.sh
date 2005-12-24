#!/bin/sh
if [ ! -n "$PERL" ]
then
	PERL=perl
fi
#$PERL -MExtUtils::Command::MM -e "test_harness()" pidl/tests/*.pl
$PERL -MExtUtils::Command::MM -e "test_harness()" pidl/tests/parse_idl.pl

