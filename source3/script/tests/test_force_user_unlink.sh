#!/bin/sh
#
# Test unlink on share with "force user"
#
# Copyright (C) 2021 Ralph Boehme

incdir=$(dirname $0)/../../../testprogs/blackbox
. $incdir/subunit.sh
. $incdir/common_test_fns.inc

smbclient="$BINDIR/smbclient"
error_inject_conf=$(dirname ${SMB_CONF_PATH})/error_inject.conf
failed=0

test_forced_user_can_delete() {
    out=$($smbclient -U $DOMAIN/$USERNAME%$PASSWORD //$SERVER_IP/force_user_error_inject -c "rm dir/file")
    if [ $? -ne 0 ] ; then
	echo $out
	return 1
    fi
    tmp=$(echo $out | grep NT_STATUS_ )
    if [ $? -eq 0 ] ; then
	return 1
    fi
    return 0
}

echo "error_inject:unlinkat = EACCES" > ${error_inject_conf}

$smbclient -U $DOMAIN/$USERNAME%$PASSWORD //$SERVER_IP/force_user_error_inject -c "mkdir dir" || failed=`expr $failed + 1`
$smbclient -U $DOMAIN/$USERNAME%$PASSWORD //$SERVER_IP/force_user_error_inject -c "put WHATSNEW.txt dir/file" || failed=`expr $failed + 1`

testit "test_forced_user_can_delete" test_forced_user_can_delete || failed=`expr $failed + 1`

rm ${error_inject_conf}

# Clean up after ourselves.
$smbclient -U $DOMAIN/$USERNAME%$PASSWORD //$SERVER_IP/force_user_error_inject -c "del dir/file; rmdir dir"

testok $0 $failed
