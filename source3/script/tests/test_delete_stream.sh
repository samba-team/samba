#!/bin/sh
#
# this verifies that deleting a stream uses the correct ACL
# when using vfs_acl_xattr.
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

incdir=$(dirname $0)/../../../testprogs/blackbox
. $incdir/subunit.sh


setup_testfile()
{
	touch $PREFIX/file
	echo stream > $PREFIX/stream

	$SMBCLIENT //$SERVER/$SHARE -U $USERNAME%$PASSWORD -c "mkdir dir" || return 1
	$SMBCLIENT //$SERVER/$SHARE -U $USERNAME%$PASSWORD -c "lcd $PREFIX; put file dir/file" || return 1
	$SMBCLIENT //$SERVER/$SHARE -U $USERNAME%$PASSWORD -c "lcd $PREFIX; put stream dir/file:stream" || return 1

	rm $PREFIX/file
	rm $PREFIX/stream

	#
        # Add full control ACE to the file and an ACL without "DELETE" on the
        # parent directory
	#

	$SMBCACLS //$SERVER/$SHARE -U $USERNAME%$PASSWORD -S "ACL:Everyone:ALLOWED/0x0/0x1bf" dir || return 1
	$SMBCACLS //$SERVER/$SHARE -U $USERNAME%$PASSWORD -a "ACL:Everyone:ALLOWED/0x0/0x101ff" dir/file || return 1
}

remove_testfile()
{
	$SMBCACLS //$SERVER/$SHARE -U $USERNAME%$PASSWORD -S "ACL:Everyone:ALLOWED/0x0/0x101ff" dir/file || return 1
	$SMBCACLS //$SERVER/$SHARE -U $USERNAME%$PASSWORD -S "ACL:Everyone:ALLOWED/0x0/0x101ff" dir || return 1
	$SMBCLIENT //$SERVER/$SHARE -U $USERNAME%$PASSWORD -c "rm dir/file" || return 1
	$SMBCLIENT //$SERVER/$SHARE -U $USERNAME%$PASSWORD -c "rmdir dir" || return 1
}

set_win_owner()
{
	local owner=$1

	$SMBCACLS //$SERVER/$SHARE dir/file -U $USERNAME%$PASSWORD -C "$owner" || return 1
}

delete_stream()
{
        #
        # Setup a file with a stream where we're not the owner and
        # have delete rights. Bug 15126 would trigger a fallback to
        # "acl_xattr:default acl style" because fetching the stored
        # ACL would fail. The stored ACL allows deleting the stream
        # but the synthesized default ACL does not, so the deletion
        # of the stream should work, but it fails if we have the bug.
        #

        # Now try deleting the stream
	out=$($SMBCLIENT //$SERVER/$SHARE -U $USERNAME%$PASSWORD -c "wdel 0x20 dir/file:stream") || return 1

	#
	# Bail out in case we get any sort of NT_STATUS_* error, should be
	# NT_STATUS_ACCESS_DENIED, but let's not slip through any other error.
	#
	echo "$out" | grep NT_STATUS_ && return 1

	return 0
}

win_owner_is()
{
	local expected_owner=$1
	local actual_owner

	$SMBCACLS //$SERVER/$SHARE dir/file -U $USERNAME%$PASSWORD
	actual_owner=$($SMBCACLS //$SERVER/$SHARE dir/file -U $USERNAME%$PASSWORD | sed -rn 's/^OWNER:(.*)/\1/p')
	echo "actual_owner = $actual_owner"
	if ! test "x$actual_owner" = "x$expected_owner"; then
		echo "Actual owner of dir/file is $actual_owner', expected $expected_owner"
		return 1
	fi
	return 0
}

# Create a testfile
testit "create testfile" setup_testfile $SHARE || exit 1

# Grant SeRestorePrivilege to the user so we can change the owner
testit "grant SeRestorePrivilege" $NET rpc rights grant $USERNAME SeRestorePrivilege -U $USERNAME%$PASSWORD -I $SERVER_IP || exit 1

# We have SeRestorePrivilege, so both give and take ownership must succeed
testit "give owner with SeRestorePrivilege" set_win_owner "$SERVER\user1" || exit 1
testit "verify owner" win_owner_is "$SERVER/user1" || exit 1

# Now try to remove the stream on the testfile
testit "delete stream" delete_stream $SHARE afile || exit 1

# Remove testfile
testit "remove testfile" remove_testfile $SHARE || exit 1

# Revoke SeRestorePrivilege, give ownership must fail now with NT_STATUS_INVALID_OWNER
testit "revoke SeRestorePrivilege" $NET rpc rights revoke $USERNAME SeRestorePrivilege -U $USERNAME%$PASSWORD -I $SERVER_IP || exit 1

exit 0
