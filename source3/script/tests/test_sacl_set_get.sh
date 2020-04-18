#!/bin/sh
#
# Runs the smbtorture3 SMB2-SACL test
# that requres SeSecurityPrivilege
# against Samba.
#

if [ $# -lt 7 ]; then
    echo "Usage: $0 SERVER SERVER_IP USERNAME PASSWORD SMBTORTURE3 NET SHARE"
    exit 1
fi

SERVER="$1"
SERVER_IP="$2"
USERNAME="$3"
PASSWORD="$4"
SMBTORTURE3="$5"
NET="$6"
SHARE="$7"

failed=0

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

sacl_set_get() {
    out=$($SMBTORTURE3 //$SERVER_IP/$SHARE -U $USERNAME%$PASSWORD SMB2-SACL)
    if [ $? -ne 0 ] ; then
	echo "SMB2-SACL failed"
	echo "$out"
	return 1
    fi
}

# Grant SeSecurityPrivilege to the user
testit "grant SeSecurityPrivilege" $NET rpc rights grant $USERNAME SeSecurityPrivilege -U $USERNAME%$PASSWORD -I $SERVER_IP || failed=`expr $failed + 1`

# Run the tests.
testit "SACL set_get" sacl_set_get || failed=`expr $failed + 1`

# Revoke SeSecurityPrivilege
testit "revoke SeSecurityPrivilege" $NET rpc rights revoke $USERNAME SeSecurityPrivilege -U $USERNAME%$PASSWORD -I $SERVER_IP || failed=`expr $failed + 1`

exit $failed
