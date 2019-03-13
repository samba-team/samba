#!/bin/sh

# This runs smbstatus tests

if [ $# -lt 12 ]; then
    echo "Usage: test_smbstatus.sh SERVER SERVER_IP DOMAIN USERNAME PASSWORD USERID LOCAL_PATH PREFIX SMBCLIENT CONFIGURATION PROTOCOL"
    exit 1
fi

SERVER="${1}"
SERVER_IP="${2}"
DOMAIN="${3}"
USERNAME="${4}"
PASSWORD="${5}"
USERID="${6}"
LOCAL_PATH="${7}"
PREFIX="${8}"
SMBCLIENT="${9}"
SMBSTATUS="${10}"
CONFIGURATION="${11}"
PROTOCOL="${12}"

shift 12

RAWARGS="${CONFIGURATION} -m${PROTOCOL}"
ADDARGS="${RAWARGS} $@"

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

test_smbstatus()
{
    local cmdfile=$PREFIX/smbclient_commands
    local tmpfile=$PREFIX/smclient_lock_file
    local file=smclient_lock_file
    local cmd=""
    local ret=0
    local userid=$(id -u $USERNAME)

    cat > $tmpfile <<EOF
What a Wurst!
EOF
    cat > $cmdfile <<EOF
lcd $PREFIX_ABS
put $file
open $file
!UID_WRAPPER_INITIAL_RUID=0 UID_WRAPPER_INITIAL_EUID=0 $SMBSTATUS
close 1
rm $file
quit
EOF

    cmd="CLI_FORCE_INTERACTIVE=yes $SMBCLIENT -U$USERNAME%$PASSWORD //$SERVER/tmp -I $SERVER_IP $ADDARGS --quiet < $cmdfile 2>&1"
    eval echo "$cmd"
    out=$(eval $cmd)
    ret=$?
    rm -f $cmpfile
    rm -f $tmpfile

    if [ $ret -ne 0 ] ; then
       echo "Failed to run smbclient with error $ret"
       echo "$out"
       false
       return
    fi

    echo "$out" | grep -c 'NT_STATUS_'
    ret=$?
    if [ $ret -eq 0 ] ; then
       echo "Failed: got an NT_STATUS error!"
       echo "$out"
       false
       return
    fi

    echo "$out" | grep "$userid[ ]*DENY_NONE"
    ret=$?
    if [ $ret != 0 ] ; then
        echo "Failed to find userid in smbstatus locked file output"
        echo "$out"
        false
        return
    fi

    return 0
}

test_smbstatus_resolve_uids()
{
    local cmdfile=$PREFIX/smbclient_commands
    local tmpfile=$PREFIX/smclient_lock_file
    local file=smclient_lock_file
    local cmd=""
    local ret=0
    local userid=$(id -u $USERNAME)

    cat > $tmpfile <<EOF
What a Wurst!
EOF
    cat > $cmdfile <<EOF
lcd $PREFIX_ABS
put $file
open $file
!UID_WRAPPER_INITIAL_RUID=0 UID_WRAPPER_INITIAL_EUID=0 $SMBSTATUS --resolve-uids
close 1
rm $file
quit
EOF

    cmd="CLI_FORCE_INTERACTIVE=yes $SMBCLIENT -U$USERNAME%$PASSWORD //$SERVER/tmp -I $SERVER_IP $ADDARGS --quiet < $cmdfile 2>&1"
    eval echo "$cmd"
    out=$(eval $cmd)
    ret=$?
    rm -f $cmpfile
    rm -f $tmpfile

    if [ $ret -ne 0 ] ; then
       echo "Failed to run smbclient with error $ret"
       echo "$out"
       false
       return
    fi

    echo "$out" | grep -c 'NT_STATUS_'
    ret=$?
    if [ $ret -eq 0 ] ; then
       echo "Failed: got an NT_STATUS error!"
       echo "$out"
       false
       return
    fi

    echo "$out" | grep "$USERNAME[ ]*DENY_NONE"
    ret=$?
    if [ $ret != 0 ] ; then
        echo "Failed to find userid in smbstatus locked file output"
        echo "$out"
        false
        return
    fi

    return 0
}

testit "plain" \
    test_smbstatus || \
    failed=`expr $failed + 1`

testit "resolve_uids" \
    test_smbstatus || \
    failed=`expr $failed + 1`

testok $0 $failed
