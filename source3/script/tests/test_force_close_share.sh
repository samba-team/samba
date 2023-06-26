#!/usr/bin/env bash
#
# Test smbcontrol close-share command.
#
# Copyright (C) 2020 Volker Lendecke
# Copyright (C) 2020 Jeremy Allison
#
# Note this is designed to be run against
# the aio_delay_inject share which is preconfigured
# with 2 second delays on pread/pwrite.

if [ $# -lt 6 ]; then
	echo Usage: $0 SERVERCONFFILE SMBCLIENT SMBCONTROL IP aio_delay_inject_sharename PREFIX
	exit 1
fi

CONFIGURATION=$1
smbclient=$2
SMBCONTROL=$3
SERVER=$4
SHARE=$5
PREFIX=$6
shift 6

# Do not let deprecated option warnings muck this up
SAMBA_DEPRECATED_SUPPRESS=1
export SAMBA_DEPRECATED_SUPPRESS

incdir=$(dirname $0)/../../../testprogs/blackbox
. $incdir/subunit.sh
. $incdir/common_test_fns.inc

failed=0

mkdir -p $PREFIX/private

FIFO_STDIN="$PREFIX/smbclient-stdin"
FIFO_STDOUT="$PREFIX/smbclient-stdout"
FIFO_STDERR="$PREFIX/smbclient-stderr"
TESTFILE="$PREFIX/testfile"

rm -f $FIFO_STDIN $FIFO_STDOUT $FIFO_STDERR $TESTFILE 2>/dev/null

# Create the smbclient communication pipes.
mkfifo $FIFO_STDIN $FIFO_STDOUT $FIFO_STDERR
if [ $? -ne 0 ]; then
	echo "Failed to create fifos"
	exit 1
fi

# Create a large-ish testfile
head -c 100MB /dev/zero >$TESTFILE

CLI_FORCE_INTERACTIVE=1
export CLI_FORCE_INTERACTIVE

${smbclient} //${SERVER}/${SHARE} ${CONFIGURATION} -U${USER}%${PASSWORD} \
	<$FIFO_STDIN >$FIFO_STDOUT 2>$FIFO_STDERR &
CLIENT_PID=$!

count=0
while [ 1 ]; do
	if [ $count -ge 20 ]; then
		echo "Failed to start smbclient"
		exit 1
	fi
	kill -0 $CLIENT_PID
	if [ $? -eq 0 ]; then
		break
	fi
	sleep 0.5
	count=$((count + 1))
done

exec 100>$FIFO_STDIN 101<$FIFO_STDOUT 102<$FIFO_STDERR

# consume the smbclient startup messages
head -n 1 <&101

# Ensure we're putting a fresh file.
echo "lcd $(dirname $TESTFILE)" >&100
echo "del testfile" >&100
echo "put testfile" >&100

sleep 0.2

# Close the aio_delay_inject share whilst we have outstanding writes.

testit "smbcontrol" ${SMBCONTROL} ${CONFIGURATION} smbd close-share ${SHARE} ||
	failed=$(expr $failed + 1)

sleep 0.5

# If we get one or more NT_STATUS_NETWORK_NAME_DELETED
# or NT_STATUS_INVALID_HANDLE on stderr from the writes we
# know the server stayed up and didn't crash when the
# close-share removed the share.
#
# BUG: https://bugzilla.samba.org/show_bug.cgi?id=14301
#
COUNT=$(head -n 2 <&102 |
	grep -e NT_STATUS_NETWORK_NAME_DELETED -e NT_STATUS_INVALID_HANDLE |
	wc -l)

testit "Verify close-share did cancel the file put" \
	test $COUNT -ge 1 || failed=$(expr $failed + 1)

kill ${CLIENT_PID}

# Remove the testfile from the server
test_smbclient "remove_testfile" \
	'del testfile; quit' //${SERVER}/${SHARE} -U${USER}%${PASSWORD} ||
	failed=$(expr $failed + 1)

testok $0 $failed
