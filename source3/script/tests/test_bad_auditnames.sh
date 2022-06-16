#!/bin/sh

# this tests a full audit share with bad VFS
# names will not allow connection.
# BUG: https://bugzilla.samba.org/show_bug.cgi?id=15098

if [ $# -lt 5 ]; then
	cat <<EOF
Usage: $0 SERVER SHARE USERNAME PASSWORD SMBCLIENT
EOF
	exit 1
fi

SERVER="$1"
SHARE="$2"
USERNAME="$3"
PASSWORD="$4"
SMBCLIENT="$5"
SMBCLIENT="$VALGRIND ${SMBCLIENT}"

incdir=$(dirname "$0")/../../../testprogs/blackbox
. "$incdir/subunit.sh"

can_connect()
{
	$SMBCLIENT //"$SERVER"/"$SHARE" -U"$USERNAME"%"$PASSWORD" -c "ls" | grep "tree connect failed: NT_STATUS_UNSUCCESSFUL" >/dev/null 2>&1
}

testit "Cannot connect to share $SHARE" can_connect || failed=$((failed + 1))
