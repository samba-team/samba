#!/bin/sh
#
# Blackbox test for share with preserve case options
#
# https://bugzilla.samba.org/show_bug.cgi?id=10650

if [ $# -lt 6 ]; then
cat <<EOF
Usage: test_preserve_case.sh SERVER DOMAIN USERNAME PASSWORD PREFIX SMBCLIENT
EOF
exit 1;
fi

SERVER=$1
DOMAIN=$2
USERNAME=$3
PASSWORD=$4
PREFIX=$5
smbclient=$6
if [ $# -gt 6 ]; then
	PROTOCOL_LIST=$7
	shift 7
else
	PROTOCOL_LIST="NT1 SMB2 SMB3"
	shift 6
fi
failed=0

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

test_smbclient() {
	name="$1"
	share="$2"
	cmd="$3"
	shift
	shift
	subunit_start_test "$name"
	output=$($VALGRIND $smbclient //$SERVER/$share -c "$cmd" $@ 2>&1)
	status=$?
	if [ x$status = x0 ]; then
		subunit_pass_test "$name"
	else
		echo "$output" | subunit_fail_test "$name"
	fi
	return $status
}

SHARE="lowercase"

for PROTOCOL in $PROTOCOL_LIST; do
	test_smbclient "Test lowercase ls 1 ($PROTOCOL)" $SHARE "ls 1" -U$USERNAME%$PASSWORD -m$PROTOCOL || failed=`expr $failed + 1`
	test_smbclient "Test lowercase get 1 ($PROTOCOL)" $SHARE "get 1 LOCAL_1" -U$USERNAME%$PASSWORD -m$PROTOCOL || failed=`expr $failed + 1`
	rm -f LOCAL_1

	test_smbclient "Test lowercase ls A ($PROTOCOL)"  $SHARE "ls A" -U$USERNAME%$PASSWORD -m$PROTOCOL || failed=`expr $failed + 1`
	test_smbclient "Test lowercase get A ($PROTOCOL)" $SHARE "get A LOCAL_A" -U$USERNAME%$PASSWORD -m$PROTOCOL || failed=`expr $failed + 1`
	rm -f LOCAL_A

	test_smbclient "Test lowercase ls z ($PROTOCOL)"  $SHARE "ls z" -U$USERNAME%$PASSWORD -m$PROTOCOL || failed=`expr $failed + 1`
	test_smbclient "Test lowercase get z ($PROTOCOL)" $SHARE "get z LOCAL_Z" -U$USERNAME%$PASSWORD -m$PROTOCOL || failed=`expr $failed + 1`
	rm -f LOCAL_Z
done

SHARE="lowercase-30000"

for PROTOCOL in $PROTOCOL_LIST; do
	test_smbclient "Test lowercase ls 25839 ($PROTOCOL)" $SHARE "ls 25839" -U$USERNAME%$PASSWORD -m$PROTOCOL || failed=`expr $failed + 1`

	test_smbclient "Test lowercase ls 1 ($PROTOCOL)" $SHARE "ls 1" -U$USERNAME%$PASSWORD -m$PROTOCOL || failed=`expr $failed + 1`
	test_smbclient "Test lowercase get 1 ($PROTOCOL)" $SHARE "get 1 LOCAL_1" -U$USERNAME%$PASSWORD -m$PROTOCOL || failed=`expr $failed + 1`
	rm -f LOCAL_1

	test_smbclient "Test lowercase ls A ($PROTOCOL)"  $SHARE "ls A" -U$USERNAME%$PASSWORD -m$PROTOCOL || failed=`expr $failed + 1`
	test_smbclient "Test lowercase get A ($PROTOCOL)" $SHARE "get A LOCAL_A" -U$USERNAME%$PASSWORD -m$PROTOCOL || failed=`expr $failed + 1`
	rm -f LOCAL_A

	test_smbclient "Test lowercase ls z ($PROTOCOL)"  $SHARE "ls z" -U$USERNAME%$PASSWORD -m$PROTOCOL || failed=`expr $failed + 1`
	test_smbclient "Test lowercase get z ($PROTOCOL)" $SHARE "get z LOCAL_Z" -U$USERNAME%$PASSWORD -m$PROTOCOL || failed=`expr $failed + 1`
	rm -f LOCAL_Z
done

exit $failed
