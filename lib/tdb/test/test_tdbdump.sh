#!/bin/sh
# Test dumping of tdb database
# Copyright (C) 2024 Christof Schmitt <cs@samba.org>

if [ $# -lt 3 ]; then
	echo "Usage: $0 TDB_FILE EXPECTED_DUMP EXPECTED_DUMP_X"
	exit 1
fi

TDB_FILE=$1
EXPECTED_DUMP=$2
EXPECTED_DUMP_X=$3
TEMP_DUMP=tempdump.txt

failed=0

timestamp()
{
	date -u +'time: %Y-%m-%d %H:%M:%S.%6NZ' | sed 's/\..*NZ$/.000000Z/'
}

subunit_fail_test()
{
	timestamp
	printf 'failure: %s [\n' "$1"
	cat -
	echo "]"
}

testit()
{
	name="$1"
	shift
	cmdline="$@"
	timestamp
	printf 'test: %s\n' "$1"
	output=$($cmdline 2>&1)
	status=$?
	if [ x$status = x0 ]; then
		timestamp
		printf 'success: %s\n' "$name"
	else
		echo "$output" | subunit_fail_test "$name"
	fi
	return $status
}

$BINDIR/tdbdump $TDB_FILE > $TEMP_DUMP
testit "Verifying tdbdump" cmp $TEMP_DUMP $EXPECTED_DUMP \
	|| failed=$(expr $failed + 1)

$BINDIR/tdbdump -x $TDB_FILE > $TEMP_DUMP
testit "Verifying tdbdump -x" cmp $TEMP_DUMP $EXPECTED_DUMP_X \
	|| failed=$(expr $failed + 1)

rm $TEMP_DUMP

exit $failed
