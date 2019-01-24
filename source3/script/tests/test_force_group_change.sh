#!/bin/sh

# Copyright (c) Jeremy Allison <jra@samba.org>
# License: GPLv3
# Regression test for BUG:https://bugzilla.samba.org/show_bug.cgi?id=13690

if [ $# -lt 6 ]; then
	echo "Usage: test_force_group_change.sh SERVER USERNAME PASSWORD LOCAL_PATH SMBCLIENT SMBCONTROL"
	exit 1
fi

SERVER="${1}"
USERNAME="${2}"
PASSWORD="${3}"
LOCAL_PATH="${4}"
SMBCLIENT="${5}"
SMBCONTROL="${6}"
shift 6

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

test_force_group_change()
{
#
# A SMB_CONF variable passed in here is the client smb.conf.
# We need to convert to the server.conf file from
# the LOCAL_PATH variable.
#
SERVER_CONFIG=`dirname $LOCAL_PATH`/lib/server.conf
SERVER_CONFIG_SAVE=${SERVER_CONFIG}.bak
SERVER_CONFIG_NEW=${SERVER_CONFIG}.new
cp $SERVER_CONFIG $SERVER_CONFIG_SAVE

sed -e 's/#\tforce group = everyone/\tforce group = everyone/' <${SERVER_CONFIG} >${SERVER_CONFIG_NEW}

    tmpfile=$PREFIX/smbclient_force_group_change_commands
    cat > $tmpfile <<EOF
ls
!cp ${SERVER_CONFIG_NEW} ${SERVER_CONFIG}
!${SMBCONTROL} --configfile=${SERVER_CONFIG} all reload-config
ls
!cp ${SERVER_CONFIG_SAVE} ${SERVER_CONFIG}
!${SMBCONTROL} --configfile=${SERVER_CONFIG} all reload-config
quit
EOF

    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/force_group_test $CONFIGURATION < $tmpfile 2>&1'
    eval echo "$cmd"
    out=$(eval $cmd)
    ret=$?
    rm -f $tmpfile
    rm -f $SERVER_CONFIG_SAVE
    rm -f $SERVER_CONFIG_NEW

    echo "$out" | grep 'NT_STATUS_CONNECTION_DISCONNECTED'
    ret=$?
    if [ $ret -eq 0 ] ; then
       # Client was disconnected as server crashed.
       echo "$out"
       return 1
    fi

    return 0
}

testit "test force group change" \
    test_force_group_change || \
    failed=`expr $failed + 1`

testok $0 $failed
