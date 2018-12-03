#!/bin/sh

# Copyright (c) Andreas Schneider <asn@samba.org>
# License: GPLv3

if [ $# -lt 7 ]; then
	echo "Usage: test_homes.sh SERVER USERNAME PASSWORD LOCAL_PATH PREFIX SMBCLIENT CONFIGURATION"
	exit 1
fi

SERVER="${1}"
USERNAME="${2}"
PASSWORD="${3}"
LOCAL_PATH="${4}"
PREFIX="${5}"
SMBCLIENT="${6}"
CONFIGURATION="${7}"
shift 7

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

test_gooduser_home()
{
    tmpfile=$PREFIX/smbclient_homes_gooduser_commands
    cat > $tmpfile <<EOF
ls
quit
EOF

    USERNAME=gooduser

    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/$USERNAME $CONFIGURATION < $tmpfile 2>&1'
    eval echo "$cmd"
    out=$(eval $cmd)
    ret=$?
    rm -f $tmpfile

    if [ $ret -ne 0 ] ; then
       echo "$out"
       echo "failed to connect error $ret"
       return 1
    fi

    echo "$out" | grep 'Try "help" to get a list of possible commands.'
    ret=$?
    if [ $ret -ne 0 ] ; then
       echo "$out"
       echo 'failed - should get: Try "help" to get a list of possible commands.'
       return 1
    fi

    return 0
}

test_eviluser_home()
{
    tmpfile=$PREFIX/smbclient_homes_eviluser_commands
    cat > $tmpfile <<EOF
ls
quit
EOF

    USERNAME=eviluser

    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/$USERNAME $CONFIGURATION < $tmpfile 2>&1'
    eval echo "$cmd"
    out=$(eval $cmd)
    ret=$?
    rm -f $tmpfile

    if [ $ret -ne 1 ] ; then
       echo "$out"
       echo "The server should reject connecting ret=$ret"
       return 1
    fi

    echo "$out" | grep 'NT_STATUS_BAD_NETWORK_NAME'
    ret=$?
    if [ $ret -ne 0 ] ; then
       echo "$out"
       echo 'failed - should get: NT_STATUS_BAD_NETWORK_NAME.'
       return 1
    fi

    return 0
}

test_slashuser_home()
{
    tmpfile=$PREFIX/smbclient_homes_slashuser_commands
    cat > $tmpfile <<EOF
ls
quit
EOF

    USERNAME=slashuser

    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/$USERNAME $CONFIGURATION < $tmpfile 2>&1'
    eval echo "$cmd"
    out=$(eval $cmd)
    ret=$?
    rm -f $tmpfile

    if [ $ret -ne 1 ] ; then
       echo "$out"
       echo "The server should reject connecting ret=$ret"
       return 1
    fi

    echo "$out" | grep 'NT_STATUS_BAD_NETWORK_NAME'
    ret=$?
    if [ $ret -ne 0 ] ; then
       echo "$out"
       echo 'failed - should get: NT_STATUS_BAD_NETWORK_NAME.'
       return 1
    fi

    return 0
}

testit "test gooduser home" \
    test_gooduser_home || \
    failed=`expr $failed + 1`

testit "test eviluser home reject" \
    test_eviluser_home || \
    failed=`expr $failed + 1`

testit "test slashuser home reject" \
    test_slashuser_home || \
    failed=`expr $failed + 1`

testok $0 $failed
