#!/bin/sh
#
# Test 'net tdb' command.
#
# Verify that the command returns the correct information in the
# expected format. The 'dump' option is tested, but the output is not
# checked, since the internal data structure could change in the
# future.
#
# Copyright (C) 2017 Christof Schmitt

if [ $# -lt 7 ]; then
	cat <<EOF
Usage: $0 SMBCLIENT SERVER SHARE USER PASS CONFIGURATION LOCALPATH LOCKDIR
EOF
	exit 1
fi

SMBCLIENT=$1
SERVER=$2
SHARE=$3
USER=$4
PASS=$5
CONFIGURATION=$6
LOCALPATH=$7
LOCKDIR=$8

FILENAME=net_tdb_testfile

samba_tdbtool=tdbtool
if test -x "$BINDIR/tdbtool"; then
	samba_tdbtool="$BINDIR/tdbtool"
fi

failed=0

incdir=$(dirname "$0")/../../../testprogs/blackbox
# shellcheck source=testprogs/blackbox/subunit.sh
. "$incdir/subunit.sh"

touch "$LOCALPATH/$FILENAME"

printf "open %s\n"'!sleep 10'"\n" ${FILENAME} |
	"$SMBCLIENT" "//$SERVER/$SHARE" -U"$USER%$PASS" &
SMBCLIENTPID=$!

# Give smbclient a chance to open the file
sleep 1

testit "Looking for record key of open file" \
	"$samba_tdbtool" "$LOCKDIR/locking.tdb" hexkeys ||
	failed=$((failed + 1))

# The assumption here is that only one file is open, so only one
# record can exist in the database.

echo "=== Debug Output for 'tdbtool locking.tdb hexkeys' =="
$samba_tdbtool "$LOCKDIR/locking.tdb" hexkeys
echo "=== End Debug Output ==="

# The above code produces the following output:
#
# === Debug Output for 'tdbtool locking.tdb hexkeys' ==
# key 24 bytes
# [000] 2B 00 00 00 00 00 00 00  24 40 17 03 00 00 00 00  +...... $@.....
# [010] 00 00 00 00 00 00 00 00                           .......
#
# === End Debug Output ===
#
# Select only valid hex byte values and join them together
key="0x$("$samba_tdbtool" "$LOCKDIR/locking.tdb" hexkeys |
      awk '/^key/ && seen { exit }
           /^key/ { seen=1; next }
           /^\[/ { for(i=2; i<=NF; i++) if($i ~ /^[0-9A-Fa-f][0-9A-Fa-f]$/) printf "%s", $i }')"

echo "=== Debug Output for key =="
echo "${key}"
echo "=== End Debug Output ==="

testit "Looking for open file in locking.tdb" \
	"$BINDIR/net" "$CONFIGURATION" tdb locking "$key" ||
	failed=$((failed + 1))
out=$("$BINDIR/net" "$CONFIGURATION" tdb locking "$key")

out=$("$BINDIR/net" "$CONFIGURATION" tdb locking "$key" |
	grep 'Share path: ' | sed -e 's/Share path: \+//')
testit "Verify pathname in output" \
	test "$out" = "$LOCALPATH" ||
	failed=$((failed + 1))

out=$("$BINDIR/net" "$CONFIGURATION" tdb locking "$key" |
	grep 'Name:' | sed -e 's/Name: \+//')
testit "Verify filename in output" \
	test "$out" = "$FILENAME" ||
	failed=$((failed + 1))

out=$("$BINDIR/net" "$CONFIGURATION" tdb locking "$key" |
	grep 'Number of share modes:' |
	sed -e 's/Number of share modes: \+//')
testit "Verify number of share modes in output" \
	test "$out" = "1" ||
	failed=$((failed + 1))

testit "Complete record dump" \
	"$BINDIR/net" "$CONFIGURATION" tdb locking "$key" dump ||
	failed=$((failed + 1))

"$BINDIR/net" "$CONFIGURATION" tdb locking "$key" dump | grep -q "$FILENAME"
RC=$?
testit "Verify filename in dump output" \
	test $RC = 0 ||
	failed=$((failed + 1))
"$BINDIR/net" "$CONFIGURATION" tdb locking "$key" dump | grep -q "$LOCALPATH"
RC=$?
testit "Verify share path in dump output" \
	test $RC = 0 ||
	failed=$((failed + 1))

kill $SMBCLIENTPID

testok "$0" "$failed"
