#!/bin/bash
#
# Test smbcontrol close-share command.
#
# Copyright (C) 2020 Volker Lendecke
# Copyright (C) 2020 Jeremy Allison
#
# Note this is designed to be run against
# the aio_delay_inject share which is preconfigured
# with 2 second delays on pread/pwrite.

if [ $# -lt 5 ]; then
    echo Usage: test_share_force_close.sh \
	 SERVERCONFFILE SMBCLIENT SMBCONTROL IP aio_delay_inject_sharename
exit 1
fi

CONF=$1
SMBCLIENT=$2
SMBCONTROL=$3
SERVER=$4
SHARE=$5

incdir=$(dirname $0)/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

# Create the smbclient communication pipes.
rm -f smbclient-stdin smbclient-stdout smbclient-stderr
mkfifo smbclient-stdin smbclient-stdout smbclient-stderr

# Create a large-ish testfile
rm testfile
head -c 20MB /dev/zero >testfile

CLI_FORCE_INTERACTIVE=1; export CLI_FORCE_INTERACTIVE

${SMBCLIENT} //${SERVER}/${SHARE} ${CONF} -U${USER}%${PASSWORD} \
	     < smbclient-stdin > smbclient-stdout 2>smbclient-stderr &
CLIENT_PID=$!

sleep 1

exec 100>smbclient-stdin  101<smbclient-stdout 102<smbclient-stderr

# consume the smbclient startup messages
head -n 1 <&101
head -n 1 <&102

# Ensure we're putting a fresh file.
echo "del testfile" >&100
echo "put testfile" >&100

sleep 1

# Close the aio_delay_inject share whilst we have outstanding writes.

testit "smbcontrol" ${SMBCONTROL} ${CONF} smbd close-share ${SHARE} ||
    failed=$(expr $failed + 1)

sleep 1

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

# Rerun smbclient to remove the testfile on the server.
rm -f smbclient-stdin smbclient-stdout smbclient-stderr testfile
mkfifo smbclient-stdin smbclient-stdout

${SMBCLIENT} //${SERVER}/${SHARE} ${CONF} -U${USER}%${PASSWORD} \
	     < smbclient-stdin > smbclient-stdout &
CLIENT_PID=$!

sleep 1

exec 100>smbclient-stdin  101<smbclient-stdout

echo "del testfile" >&100

sleep 1

kill ${CLIENT_PID}

rm -f smbclient-stdin smbclient-stdout testfile

testok $0 $failed
