#!/bin/sh

# regression test for dfs access with wide links enabled on dfs share

if [ $# -lt 5 ]; then
	cat <<EOF
Usage: test_smbclient_basic.sh SERVER SERVER_IP DOMAIN USERNAME PASSWORD SMBCLIENT <smbclient arguments>
EOF
	exit 1
fi

SERVER="$1"
SERVER_IP="$2"
USERNAME="$3"
PASSWORD="$4"
smbclient="$5"
CONFIGURATION="$6"
shift 6
ADDARGS="$@"

incdir=$(dirname $0)/../../../testprogs/blackbox
. $incdir/subunit.sh
. $incdir/common_test_fns.inc

# TEST
test_smbclient "smbclient as $DOMAIN\\$USERNAME" 'ls' "//$SERVER/msdfs-share-wl" -U$DOMAIN\\$USERNAME%$PASSWORD $ADDARGS -c 'cd msdfs-src1' || failed=$(expr $failed + 1)

exit $failed
