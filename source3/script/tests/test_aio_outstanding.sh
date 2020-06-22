#!/bin/bash
#
# Test terminating an smbclient connection with outstanding
# aio requests.
#
# Note this is designed to be run against
# the aio_delay_inject share which is preconfigured
# with 2 second delays on pread/pwrite.

if [ $# -lt 4 ]; then
    echo Usage: test_aio_outstanding.sh \
	 SERVERCONFFILE SMBCLIENT IP aio_delay_inject_sharename
exit 1
fi

CONF=$1
SMBCLIENT=$2
SERVER=$3
SHARE=$4

incdir=$(dirname $0)/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0
#
# Note if we already have any panics in the smbd log.
#
panic_count_0=$(grep -c PANIC $SMBD_TEST_LOG)

# Create the smbclient communication pipes.
rm -f smbclient-stdin smbclient-stdout smbclient-stderr
mkfifo smbclient-stdin smbclient-stdout smbclient-stderr

# Create a large-ish testfile
rm aio_outstanding_testfile
head -c 20MB /dev/zero >aio_outstanding_testfile

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
echo "del aio_outstanding_testfile" >&100
echo "put aio_outstanding_testfile" >&100

sleep 2

# Terminate the smbclient write to the aio_delay_inject share whilst
# we have outstanding writes.
kill $CLIENT_PID

sleep 1

# Ensure the panic count didn't change.
#
# BUG: https://bugzilla.samba.org/show_bug.cgi?id=14301
#

panic_count_1=$(grep -c PANIC $SMBD_TEST_LOG)

# Rerun smbclient to remove the testfile on the server.
rm -f smbclient-stdin smbclient-stdout smbclient-stderr aio_outstanding_testfile
mkfifo smbclient-stdin smbclient-stdout

${SMBCLIENT} //${SERVER}/${SHARE} ${CONF} -U${USER}%${PASSWORD} \
	     < smbclient-stdin > smbclient-stdout &

sleep 1

exec 100>smbclient-stdin  101<smbclient-stdout

echo "del aio_outstanding_testfile" >&100
echo "exit" >&100

sleep 2

rm -f smbclient-stdin smbclient-stdout aio_outstanding_testfile

testit "check_panic" test $panic_count_0 -eq $panic_count_1 ||
        failed=$(expr $failed + 1)

testok $0 $failed
