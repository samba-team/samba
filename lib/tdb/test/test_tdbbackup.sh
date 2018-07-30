#!/bin/sh
# Blackbox test for tdbbackup of given ldb or tdb database
# Copyright (C) 2018 Andrew Bartlett <abartlet@samba.org>

if [ $# -lt 1 ]; then
	echo "Usage: $0 LDBFILE"
	exit 1;
fi

LDBFILE=$1

timestamp() {
  date -u +'time: %Y-%m-%d %H:%M:%S.%6NZ' | sed 's/\..*NZ$/.000000Z/'
}

subunit_fail_test () {
  timestamp
  printf 'failure: %s [\n' "$1"
  cat -
  echo "]"
}

testit () {
	name="$1"
	shift
	cmdline="$@"
	timestamp
	printf 'test: %s\n' "$1"
	output=`$cmdline 2>&1`
	status=$?
	if [ x$status = x0 ]; then
		timestamp
		printf 'success: %s\n' "$name"
	else
		echo "$output" | subunit_fail_test "$name"
	fi
	return $status
}

$BINDIR/tdbdump $LDBFILE | sort > orig_dump

testit "normal tdbbackup on tdb file" $BINDIR/tdbbackup $LDBFILE -s .bak
$BINDIR/tdbdump $LDBFILE.bak | sort > bak_dump
testit "cmp between tdbdumps of original and backup" cmp orig_dump bak_dump
rm $LDBFILE.bak
rm bak_dump

testit "readonly tdbbackup on tdb file" $BINDIR/tdbbackup $LDBFILE -s .bak -r
$BINDIR/tdbdump $LDBFILE.bak | sort > bak_dump
testit "cmp between tdbdumps of original and back dbs" cmp orig_dump bak_dump
rm $LDBFILE.bak
rm bak_dump

rm orig_dump
