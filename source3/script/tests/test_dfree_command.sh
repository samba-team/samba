#!/bin/sh
#
# Blackbox test for 'dfree command' and smbclient "l"
# command disk free printout.
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
protocol=$7

shift 7
failed=0

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

test_smbclient_dfree() {
	name="$1"
	share="$2"
	cmd="$3"
    expected="$4"
	shift
	shift
    shift
	subunit_start_test "$name"
	output=$($VALGRIND $smbclient //$SERVER/$share -c "$cmd" $@ 2>&1)
	status=$?
	if [ x$status = x0 ]; then
		received=$(echo "$output" | awk '/blocks of size/ {print $1, $5, $6}')
		if [ "$expected" = "$received" ]; then
			subunit_pass_test "$name"
		else
			echo "$output" | subunit_fail_test "$name"
		fi
	else
		echo "$output" | subunit_fail_test "$name"
	fi
	return $status
}

if [ $protocol = "SMB3" ]; then
	test_smbclient_dfree "Test dfree command share root SMB3" dfree "l" "2000 1024. 20" -U$USERNAME%$PASSWORD --option=clientmaxprotocol=SMB3 || failed=`expr $failed + 1`
	test_smbclient_dfree "Test dfree command subdir1 SMB3" dfree "cd subdir1; l" "8000 1024. 80" -U$USERNAME%$PASSWORD --option=clientmaxprotocol=SMB3 || failed=`expr $failed + 1`
	test_smbclient_dfree "Test dfree command subdir2 SMB3" dfree "cd subdir2; l" "32000 1024. 320" -U$USERNAME%$PASSWORD --option=clientmaxprotocol=SMB3 || failed=`expr $failed + 1`

elif [ $protocol = "NT1" ]; then
	test_smbclient_dfree "Test dfree command share root NT1" dfree "l" "2000 1024. 20" -U$USERNAME%$PASSWORD --option=clientmaxprotocol=NT1 || failed=`expr $failed + 1`
#SMB1 queries disk usage stat on the share's root, regardless of working directory
	test_smbclient_dfree "Test dfree command subdir1 NT1" dfree "cd subdir1; l" "2000 1024. 20" -U$USERNAME%$PASSWORD --option=clientmaxprotocol=NT1 || failed=`expr $failed + 1`

else
	echo "unsupported protocol $protocol" |  subunit_fail_test "Test dfree command"
	$failed=`expr $failed + 1`
fi
exit $failed
