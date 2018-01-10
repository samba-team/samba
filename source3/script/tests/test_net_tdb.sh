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
exit 1;
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
if test -x $BINDIR/tdbtool; then
	samba_tdbtool=$BINDIR/tdbtool
fi

failed=0

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

touch $LOCALPATH/$FILENAME

printf "open %s\n"'!sleep 10'"\n" ${FILENAME} | \
	$SMBCLIENT //$SERVER/$SHARE -U$USER%$PASS &
SMBCLIENTPID=$!

# Give smbclient a chance to open the file
sleep 1

testit "Looking for record key of open file" \
	$samba_tdbtool $LOCKDIR/locking.tdb hexkeys || \
	failed=$(expr $failed + 1)

# The assumption here is that only one file is open, so only one
# record can exist in the database.

# Output of 'tdbtool hexkeys' is in this format:
#[000] 01 FD 00 00 00 00 00 00  56 02 5C 00 00 00 00 00  ....... V.\....
#[010] 00 00 00 00 00 00 00 00                           .......
# Select only the hex data, remove space and join every thing together
key=0x$($samba_tdbtool $LOCKDIR/locking.tdb hexkeys | \
	grep '\[' | cut -c 7-56 | sed -e 's/ //g' | tr -d '\n')

testit "Looking for open file in locking.tdb" \
       $BINDIR/net $CONFIGURATION tdb locking $key || \
   failed=$(expr $failed + 1)
out=$($BINDIR/net $CONFIGURATION tdb locking $key)

out=$($BINDIR/net $CONFIGURATION tdb locking $key | \
	      grep 'Share path: ' | sed -e 's/Share path: \+//')
testit "Verify pathname in output" \
       test "$out" = "$LOCALPATH" || \
	failed=$(expr $failed + 1)

out=$($BINDIR/net $CONFIGURATION tdb locking $key | \
	      grep 'Name:' | sed -e 's/Name: \+//')
testit "Verify filename in output" \
       test "$out" = "$FILENAME" || \
	failed=$(expr $failed + 1)

out=$($BINDIR/net $CONFIGURATION tdb locking $key | \
	      grep 'Number of share modes:' | \
	      sed -e 's/Number of share modes: \+//')
testit "Verify number of share modes in output" \
       test "$out" = "1" || \
	failed=$(expr $failed + 1)

testit "Complete record dump" \
       $BINDIR/net $CONFIGURATION tdb locking $key dump || \
	failed=$(expr $failed + 1)

$BINDIR/net $CONFIGURATION tdb locking $key dump | grep -q $FILENAME
RC=$?
testit "Verify filename in dump output" \
       test $RC = 0 || \
	failed=$(expr $failed + 1)
$BINDIR/net $CONFIGURATION tdb locking $key dump | grep -q $LOCALPATH
RC=$?
testit "Verify share path in dump output" \
       test $RC = 0 || \
	failed=$(expr $failed + 1)

kill $SMBCLIENTPID

testok $0 $failed
