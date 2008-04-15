#!/bin/sh
# Blackbox tests for masktest
# Copyright (C) 2008 Andrew Tridgell
# Copyright (C) 2008 Andrew Bartlett
# based on test_smbclient.sh

failed=0

samba4bindir=`dirname $0`/../../source/bin
ndrdump=$samba4bindir/ndrdump
files=`dirname $0`/ndrdump

testit() {
	name="$1"
	shift
	cmdline="$*"
	echo "test: $name"
	$cmdline
	status=$?
	if [ x$status = x0 ]; then
		echo "success: $name"
	else
		echo "failure: $name"
	fi
	return $status
}

testit "ndrdump with in" $VALGRIND $ndrdump samr samr_CreateUser in $files/samr-CreateUser-in.dat $@ || failed=`expr $failed + 1`
testit "ndrdump with out" $VALGRIND $ndrdump samr samr_CreateUser out $files/samr-CreateUser-out.dat $@ || failed=`expr $failed + 1`
testit "ndrdump with --context-file" $VALGRIND $ndrdump --context-file $files/samr-CreateUser-in.dat samr samr_CreateUser out $files/samr-CreateUser-out.dat $@ || failed=`expr $failed + 1`
testit "ndrdump with validate" $VALGRIND $ndrdump --validate samr samr_CreateUser in $files/samr-CreateUser-in.dat $@ || failed=`expr $failed + 1`

exit $failed
