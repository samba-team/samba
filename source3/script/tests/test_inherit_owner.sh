#!/bin/sh

# this tests "inherit owner" config parameter
# currently needs to run in SMB1 mode, because it uses UNIX
# extensions to fetch the UNIX owner of a file.

if [ $# -lt 10 ]; then
cat <<EOF
Usage: $0 SERVER USERNAME PASSWORD PREFIX SMBCLIENT SMBCACLS NET SHARE INH_WIN INH_UNIX <additional args>
EOF
exit 1;
fi

SERVER="$1"
USERNAME="$2"
PASSWORD="$3"
PREFIX="$4"
SMBCLIENT="$5"
SMBCACLS="$6"
NET="$7"
SHARE="$8"
INH_WIN="$9"
INH_UNIX="${10}"
shift 10
ADDARGS="$*"
SMBCLIENT="$VALGRIND ${SMBCLIENT} ${ADDARGS}"
SMBCACLS="$VALGRIND ${SMBCACLS} ${ADDARGS}"
NET="$VALGRIND ${NET}"

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

create_file() {
    local share=$1
    local fname=$2
    local rem_dirname=$(dirname $fname)
    local bname=$(basename $fname)
    touch $PREFIX/$bname
    $SMBCLIENT //$SERVER/$share -U $USERNAME%$PASSWORD -c "cd $rem_dirname; rm $bname" 2>/dev/null
    $SMBCLIENT //$SERVER/$share -U $USERNAME%$PASSWORD -c "cd $rem_dirname; allinfo $bname" 2>/dev/null | grep "NT_STATUS_OBJECT_NAME_NOT_FOUND" || exit 1
    $SMBCLIENT //$SERVER/$share -U $USERNAME%$PASSWORD -c "lcd $PREFIX; cd $rem_dirname; put $bname" 2>/dev/null || exit 1
}

create_dir() {
    local share=$1
    local dname=$2
    local rem_dirname=$(dirname $dname)
    local bname=$(basename $dname)
    $SMBCLIENT //$SERVER/$share -U $USERNAME%$PASSWORD -c "cd $rem_dirname; rmdir $bname" 2>/dev/null
    $SMBCLIENT //$SERVER/$share -U $USERNAME%$PASSWORD -c "cd $rem_dirname; allinfo $bname" 2>/dev/null | grep "NT_STATUS_OBJECT_NAME_NOT_FOUND" || exit 1
    $SMBCLIENT //$SERVER/$share -U $USERNAME%$PASSWORD -c "cd $rem_dirname; mkdir $bname" 2>/dev/null || exit 1
}

cleanup_file() {
    local share=$1
    local fname=$2
    local rem_dirname=$(dirname $fname)
    local bname=$(basename $fname)
    $SMBCLIENT //$SERVER/$share -U $USERNAME%$PASSWORD -c "cd $rem_dirname; rm $bname" 2>/dev/null || exit 1
}

cleanup_dir() {
    local share=$1
    local dname=$2
    local rem_dirname=$(dirname $dname)
    local bname=$(basename $dname)
    $SMBCLIENT //$SERVER/$share -U $USERNAME%$PASSWORD -c "cd $rem_dirname; rmdir $bname" 2>/dev/null || exit 1
}

set_win_owner() {
    local share=$1
    local fname=$2
    local owner=$3
    $SMBCACLS //$SERVER/$share $fname -U $USERNAME%$PASSWORD -C $owner 2>/dev/null || exit 1
}

unix_owner_id_is() {
    local share=$1
    local fname=$2
    local expected_id=$3
    local actual_id
    actual_id=$($SMBCLIENT //$SERVER/$share -U $USERNAME%$PASSWORD -c "getfacl $fname" 2>/dev/null | sed -rn 's/^# owner: (.*)/\1/p')
    if ! test "x$actual_id" = "x$expected_id" ; then
        echo "Actual uid of $share/$fname is [$actual_id] expected [$expected_id]"
        exit 1
    fi
}

get_unix_id() {
    local user=$1
    local ent
    ent=$(getent passwd $user) || exit 1
    echo "$ent" | awk -F: '{print $3}'
}

win_owner_is() {
    local share=$1
    local fname=$2
    local expected_owner=$3
    local actual_owner
    actual_owner=$($SMBCACLS //$SERVER/$share $fname -U $USERNAME%$PASSWORD 2>/dev/null | sed -rn 's/^OWNER:(.*)/\1/p')
    if ! test "x$actual_owner" = "x$expected_owner" ; then
        echo "Actual owner of $share/$fname is [$actual_owner] expected [$expected_owner]"
        exit 1
    fi
}

default_uid=$(get_unix_id $USERNAME)
alt_uid=$(get_unix_id force_user)

if [ "$INH_WIN" = "0" ] && [ "$INH_UNIX" = "0" ] ; then
    #default - file owned by creator, change-owner modifies both
    WIN_OWNER_AFTER_CREATE="$SERVER/$USERNAME"
    UNIX_OWNER_AFTER_CREATE=$(get_unix_id $USERNAME)
    WIN_OWNER_AFTER_CHOWN="$SERVER/smbget_user"
    UNIX_OWNER_AFTER_CHOWN=$(get_unix_id smbget_user)
    TEST_LABEL="default"
elif [ "$INH_WIN" = "1" ] && [ "$INH_UNIX" = "1" ] ; then
    #inherit owner=windows and unix - file owned by parent
    #owner, change-owner modifies both
    WIN_OWNER_AFTER_CREATE="$SERVER/force_user"
    UNIX_OWNER_AFTER_CREATE=$(get_unix_id force_user)
    WIN_OWNER_AFTER_CHOWN="$SERVER/smbget_user"
    UNIX_OWNER_AFTER_CHOWN=$(get_unix_id smbget_user)
    TEST_LABEL="both"
elif [ "$INH_WIN" = "0" ] && [ "$INH_UNIX" = "1" ] ; then
    #inherit owner=unix only - windows owner is creator,
    #unix owner inherited, upon change-owner only windows
    #owner is changed
    WIN_OWNER_AFTER_CREATE="$SERVER/$USERNAME"
    UNIX_OWNER_AFTER_CREATE=$(get_unix_id force_user)
    WIN_OWNER_AFTER_CHOWN="$SERVER/smbget_user"
    UNIX_OWNER_AFTER_CHOWN=$(get_unix_id force_user)
    TEST_LABEL="unix"
else
    echo "Unknown combination INH_WIN=$INH_WIN INH_UNIX=$INH_UNIX"
    exit 1
fi

# SETUP
testit "$TEST_LABEL - setup root dir" create_dir tmp tmp.$$
testit "grant SeRestorePrivilege" $NET rpc rights grant $USERNAME SeRestorePrivilege -U $USERNAME%$PASSWORD -I $SERVER || exit 1
testit "$TEST_LABEL - assign default ACL" $SMBCACLS //$SERVER/tmp tmp.$$ -U $USERNAME%$PASSWORD -S "REVISION:1,OWNER:$SERVER\force_user,GROUP:$SERVER\domusers,ACL:Everyone:ALLOWED/0x3/FULL" 2>/dev/null
# END SETUP

testit "$TEST_LABEL - create subdir under root" create_dir $SHARE tmp.$$/subdir
testit "$TEST_LABEL - verify subdir win owner" win_owner_is $SHARE tmp.$$/subdir "$WIN_OWNER_AFTER_CREATE"
testit "$TEST_LABEL - verify subdir unix owner" unix_owner_id_is $SHARE tmp.$$/subdir $UNIX_OWNER_AFTER_CREATE
testit "$TEST_LABEL - create file under root" create_file $SHARE tmp.$$/afile
testit "$TEST_LABEL - verify file win owner" win_owner_is $SHARE tmp.$$/afile "$WIN_OWNER_AFTER_CREATE"
testit "$TEST_LABEL - verify file unix owner" unix_owner_id_is $SHARE tmp.$$/afile $UNIX_OWNER_AFTER_CREATE
testit "$TEST_LABEL - change dir owner" set_win_owner $SHARE tmp.$$/subdir "$SERVER\smbget_user"
testit "$TEST_LABEL - verify subdir win owner after change" win_owner_is $SHARE tmp.$$/subdir "$WIN_OWNER_AFTER_CHOWN"
testit "$TEST_LABEL - verify subdir unix owner after change" unix_owner_id_is $SHARE tmp.$$/subdir $UNIX_OWNER_AFTER_CHOWN
testit "$TEST_LABEL - change file owner" set_win_owner $SHARE tmp.$$/afile "$SERVER\smbget_user"
testit "$TEST_LABEL - verify file win owner after change" win_owner_is $SHARE tmp.$$/afile "$WIN_OWNER_AFTER_CHOWN"
testit "$TEST_LABEL - verify file unix owner after change" unix_owner_id_is $SHARE tmp.$$/afile $UNIX_OWNER_AFTER_CHOWN
testit "$TEST_LABEL - cleanup subdir" cleanup_dir $SHARE tmp.$$/subdir
testit "$TEST_LABEL - cleanup file" cleanup_file $SHARE tmp.$$/afile
testit "$TEST_LABEL - cleanup root" cleanup_dir $SHARE tmp.$$

testit "revoke SeRestorePrivilege" $NET rpc rights revoke $USERNAME SeRestorePrivilege -U $USERNAME%$PASSWORD -I $SERVER || exit 1
