#!/bin/sh
# Blackbox tests for locktest
# Copyright (C) 2008 Andrew Tridgell
# based on test_smbclient.sh

if [ $# -lt 4 ]; then
cat <<EOF
Usage: test_locktest.sh SERVER USERNAME PASSWORD DOMAIN
EOF
exit 1;
fi

SERVER=$1
USERNAME=$2
PASSWORD=$3
DOMAIN=$4
shift 4
failed=0

samba4bindir=`dirname $0`/../../source/bin
locktest=$samba4bindir/locktest

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

testit "locktest" $VALGRIND $locktest //$SERVER/test1 //$SERVER/test2 -o 100  -W "$DOMAIN" -U"$USERNAME%$PASSWORD" -U"$USERNAME%$PASSWORD" $@ || failed=`expr $failed + 1`

exit $failed
