#!/bin/sh
#
# This verifies setting the volume serial number parameter for a share works.
#

if [ $# -lt 5 ]; then
    echo "Usage: $0 SERVER_IP USERNAME PASSWORD SHARENAME SMBCLIENT"
    exit 1
fi

SERVER_IP="$1"
USERNAME="$2"
PASSWORD="$3"
SHARENAME="$4"
SMBCLIENT="$5"

SMBCLIENT="$VALGRIND ${SMBCLIENT}"
failed=0

incdir=$(dirname "$0")/../../../testprogs/blackbox
. "$incdir/subunit.sh"

test_serial_number() {

    output=$($SMBCLIENT "//$SERVER_IP/$SHARENAME" -U "$USERNAME%$PASSWORD" -c "volume") || return 1
    echo "smbclient volume on $SHARENAME returned: \"$output\""

    expected="0xdeadbeef"
    echo "$output" | grep $expected || {
        echo "Expected output containing \"$expected\", got: \"$output\""
        return 1
    }
}

testit "volume serial number for share $SHARENAME" test_serial_number || failed=$((failed+1))

exit "$failed"
