#!/bin/sh
#
# Blackbox test for SMB2 case insensitivity
#

if [ $# -lt 6 ]; then
cat <<EOF
Usage: test_smb2_not_casesensitive SERVER SERVER_IP USERNAME PASSWORD LOCAL_PATH SMBCLIENT
EOF
exit 1;
fi

SERVER=${1}
SERVER_IP=${2}
USERNAME=${3}
PASSWORD=${4}
LOCAL_PATH=${5}
SMBCLIENT=${6}

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

# Test a file with different case works over SMB2 and later
test_access_with_different_case()
{
	tmpfile=$LOCAL_PATH/testfile.txt
	echo "foobar" > $tmpfile

	cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT -mSMB3 -U$USERNAME%$PASSWORD "$SERVER" -I $SERVER_IP -c "ls TeStFiLe.TxT" 2>&1'
	out=`eval $cmd`
	ret=$?

	rm -f $tmpfile

	if [ $ret = 0 ]; then
		return 0
	else
		echo "$out"
		echo "failed to get file with different case"
		return 1
	fi
}

# Test that a rename causes a conflict works when target name exists in
# different case
test_rename()
{
set -x
	tmpfile=$LOCAL_PATH/torename.txt
	echo "foobar" > $tmpfile
	targetfile=$LOCAL_PATH/target.txt
	touch $targetfile

	cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT -mSMB3 -U$USERNAME%$PASSWORD "$SERVER" -I $SERVER_IP -c "rename ToReNaMe.TxT TaRgEt.txt" 2>&1'
	out=`eval $cmd`
	ret=$?

	rm -f $tmpfile
	rm -f $targetfile
	rm -f $LOCAL_PATH/TaRgEt.txt

	if [ $ret = 1 -a -z "${out##*COLLISION*}" ]; then
		return 0
	else
		echo "$out"
		echo "failed to get file with different case"
		return 1
	fi
}


testit "accessing a file with different case succeeds" \
	test_access_with_different_case || \
	failed=`expr $failed + 1`

testit "renaming a file with different case succeeds" \
	test_rename || \
	failed=`expr $failed + 1`

exit $failed
