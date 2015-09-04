#!/bin/sh
#
# Blackbox test for 'dfree command'
#

if [ $# -lt 6 ]; then
cat <<EOF
Usage: test_dfree_command.sh SERVER DOMAIN USERNAME PASSWORD PREFIX SMBCLIENT
EOF
exit 1;
fi

SERVER=$1
DOMAIN=$2
USERNAME=$3
PASSWORD=$4
PREFIX=$5
smbclient=$6
shift 6
failed=0

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

test_smbclient_dfree() {
	name="$1"
	share="$2"
	cmd="$3"
	shift
	shift
	subunit_start_test "$name"
	output=$($VALGRIND $smbclient //$SERVER/$share -c "$cmd" $@ 2>&1)
	status=$?
	if [ x$status = x0 ]; then
		echo "$output" | grep "2000 blocks of size 1024. 20 blocks available" >/dev/null
		status=$?
		if [ x$status = x0 ]; then
			subunit_pass_test "$name"
		else
			echo "$output" | subunit_fail_test "$name"
		fi
	else
		echo "$output" | subunit_fail_test "$name"
	fi
	return $status
}


test_smbclient_dfree "Test dfree command" dfree "l" -U$USERNAME%$PASSWORD || failed=`expr $failed + 1`

exit $failed
