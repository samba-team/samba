#!/bin/sh

# this tests copying a file and then deleting it
# to a share using fruit:resource = stream
# BUG: https://bugzilla.samba.org/show_bug.cgi?id=15099

if [ $# -lt 6 ]; then
	cat <<EOF
Usage: $0 SERVER SHARE USERNAME PASSWORD LOCAL_PATH SMBCLIENT
EOF
	exit 1
fi

SERVER="${1}"
SHARE="${2}"
USERNAME="${3}"
PASSWORD="${4}"
LOCAL_PATH="${5}"
SMBCLIENT="${6}"
SMBCLIENT="$VALGRIND ${SMBCLIENT}"

incdir=$(dirname "$0")/../../../testprogs/blackbox
. "$incdir/subunit.sh"

failed=0

put_then_delete_file()
{
	$SMBCLIENT //"$SERVER"/"$SHARE" -U"$USERNAME"%"$PASSWORD" -c "lcd $LOCAL_PATH; put src dst; rm dst" >/dev/null 2>&1
}

rm -f "$LOCAL_PATH/src"
rm -f "$LOCAL_PATH/dst"
touch "$LOCAL_PATH/src"

testit "resource_stream" put_then_delete_file || failed=$((failed + 1))

rm -f "$LOCAL_PATH/src"
rm -f "$LOCAL_PATH/dst"

testok "$0" "$failed"
