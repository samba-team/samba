#!/bin/sh
#
# this verifies that SEC_STD_WRITE_OWNER only effectively grants take-ownership
# permissions but NOT give-ownership.
#

if [ $# -lt 9 ]; then
    echo "Usage: $0 SERVER SERVER_IP USERNAME PASSWORD PREFIX SMBCLIENT SMBCACLS NET SHARE"
    exit 1
fi

SERVER="$1"
SERVER_IP="$2"
USERNAME="$3"
PASSWORD="$4"
PREFIX="$5"
SMBCLIENT="$6"
SMBCACLS="$7"
NET="$8"
SHARE="$9"

SMBCLIENT="$VALGRIND ${SMBCLIENT}"
SMBCACLS="$VALGRIND ${SMBCACLS}"
NET="$VALGRIND ${NET}"
failed=0

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

setup_testfile() {
    local share=$1
    local fname=$2
    touch $PREFIX/$fname
    $SMBCLIENT //$SERVER/$share -U $USERNAME%$PASSWORD -c "rm $fname"
    $SMBCLIENT //$SERVER/$share -U $USERNAME%$PASSWORD -c "ls" | grep "$fname" && return 1
    $SMBCLIENT //$SERVER/$share -U $USERNAME%$PASSWORD -c "lcd $PREFIX; put $fname" || return 1
}

remove_testfile() {
    local share=$1
    local fname=$2
    $SMBCLIENT //$SERVER/$share -U $USERNAME%$PASSWORD -c "rm $fname"
}

set_win_owner() {
    local share=$1
    local fname=$2
    local owner=$3
    echo "$SMBCACLS //$SERVER/$share $fname -U $USERNAME%$PASSWORD -C '$owner'"
    $SMBCACLS //$SERVER/$share $fname -U $USERNAME%$PASSWORD -C "$owner" || return 1
}

win_owner_is() {
    local share=$1
    local fname=$2
    local expected_owner=$3
    local actual_owner

    echo "$SMBCACLS //$SERVER/$share $fname -U $USERNAME%$PASSWORD"
    $SMBCACLS //$SERVER/$share $fname -U $USERNAME%$PASSWORD
    actual_owner=$($SMBCACLS //$SERVER/$share $fname -U $USERNAME%$PASSWORD | sed -rn 's/^OWNER:(.*)/\1/p')
    echo "actual_owner = $actual_owner"
    if ! test "x$actual_owner" = "x$expected_owner" ; then
        echo "Actual owner of $share/$fname is [$actual_owner] expected [$expected_owner]"
        return 1
    fi
    return 0
}

add_ace() {
    local share=$1
    local fname=$2
    local ace=$3

    local_ace=$(printf '%s' "$ace" | sed 's|\\|/|')

    # avoid duplicate
    out=$($SMBCACLS //$SERVER/$share $fname -U $USERNAME%$PASSWORD)
    if [ $? -ne 0 ] ; then
	echo "get acl failed"
	echo "$out"
	return 1
    fi
    echo "Original ACL"
    echo $out
    echo "$out" | grep "$local_ace" && return 0

    # add it
    $SMBCACLS //$SERVER/$share $fname -U $USERNAME%$PASSWORD -a "$ace"
    if [ $? -ne 0 ] ; then
	echo "add acl failed"
	return 1
    fi

    # check it's there
    out=$($SMBCACLS //$SERVER/$share $fname -U $USERNAME%$PASSWORD)
    if [ $? -ne 0 ] ; then
	echo "get new acl failed"
	echo "$out"
	return 1
    fi
    echo "New ACL"
    echo $out
    echo "Checking if new ACL has \"$local_ace\""
    echo "$out" | grep "$local_ace" || return 1
    echo "ok"
}

chown_give_fails() {
    local share=$1
    local fname=$2
    local user=$3
    local expected_error=$4

    # this must fail
    out=$($SMBCACLS //$SERVER/$share $fname -U $USERNAME%$PASSWORD -C "$user") && return 1
    # it failed, now check it returned the expected error code
    echo "$out" | grep $expected_error || return 1
}

# Create a testfile
testit "create testfile" setup_testfile $SHARE afile || failed=`expr $failed + 1`
testit "verify owner" win_owner_is $SHARE afile "$SERVER/$USERNAME" || failed=`expr $failed + 1`

# Grant SeRestorePrivilege to the user and full rights on the file
testit "grant SeRestorePrivilege" $NET rpc rights grant $USERNAME SeRestorePrivilege -U $USERNAME%$PASSWORD -I $SERVER_IP || failed=`expr $failed + 1`
testit "grant full rights" add_ace $SHARE afile "ACL:$SERVER\\$USERNAME:ALLOWED/0x0/FULL" || failed=`expr $failed + 1`

# We have SeRestorePrivilege, so both give and take ownership must succeed
testit "give owner with SeRestorePrivilege" set_win_owner $SHARE afile "$SERVER\user1" || failed=`expr $failed + 1`
testit "verify owner" win_owner_is $SHARE afile "$SERVER/user1" || failed=`expr $failed + 1`
testit "take owner" set_win_owner $SHARE afile "$SERVER\\$USERNAME" || failed=`expr $failed + 1`
testit "verify owner" win_owner_is $SHARE afile "$SERVER/$USERNAME" || failed=`expr $failed + 1`

# Revoke SeRestorePrivilege, give ownership must fail now with NT_STATUS_INVALID_OWNER
testit "revoke SeRestorePrivilege" $NET rpc rights revoke $USERNAME SeRestorePrivilege -U $USERNAME%$PASSWORD -I $SERVER_IP || failed=`expr $failed + 1`
testit "give owner without SeRestorePrivilege" chown_give_fails $SHARE afile "$SERVER\user1" NT_STATUS_INVALID_OWNER || failed=`expr $failed + 1`

testit "delete testfile" remove_testfile $SHARE afile || failed=`expr $failed + 1`

exit $failed
