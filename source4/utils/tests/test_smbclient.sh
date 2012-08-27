#!/bin/sh
# Blackbox tests for smbclient

SERVER=$1
SERVER_IP=$2
USERNAME=$3
PASSWORD=$4
DOMAIN=$5
smbclient=$6
shift 6

failed=0

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
		failed=`expr $failed + 1`
	fi
	return $status
}

testit "Test login with --machine-pass without kerberos" $VALGRIND $smbclient -c 'ls' $CONFIGURATION //$SERVER/tmp --machine-pass -k no

testit "Test login with --machine-pass and kerberos" $VALGRIND $smbclient -c 'ls' $CONFIGURATION //$SERVER/tmp --machine-pass -k yes

exit $failed
