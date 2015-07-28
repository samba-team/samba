#!/bin/sh
#
# Blackbox test for valid users.
#

if [ $# -lt 7 ]; then
cat <<EOF
Usage: valid_users SERVER SERVER_IP DOMAIN USERNAME PASSWORD PREFIX SMBCLIENT
EOF
exit 1;
fi

SERVER=${1}
SERVER_IP=${2}
DOMAIN=${3}
USERNAME=${4}
PASSWORD=${5}
PREFIX=${6}
SMBCLIENT=${7}
shift 7
SMBCLIENT="$VALGRIND ${SMBCLIENT}"
ADDARGS="$*"

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

# Test listing a share with valid users succeeds
test_valid_users_access()
{
    tmpfile=$PREFIX/smbclient.in.$$
    prompt="foo"
    cat > $tmpfile <<EOF
ls
quit
EOF

    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT -U$USERNAME%$PASSWORD "//$SERVER/$1" -I $SERVER_IP $ADDARGS < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?
    rm -f $tmpfile

    if [ $ret != 0 ] ; then
        echo "$out"
        echo "failed accessing share with valid users with error $ret"

        false
        return
    fi

    echo "$out" | grep "$prompt" >/dev/null 2>&1

    ret=$?
    if [ $ret = 0 ] ; then
        # got the correct prompt .. succeed
        true
    else
        echo "$out"
        echo "failed listing share with valid users"
        false
    fi
}

testit "accessing a valid users share succeeds" \
   test_valid_users_access valid-users-access || \
   failed=`expr $failed + 1`

exit $failed
