#!/usr/bin/env bash
#
# Test deadtime parameter
#

if [ $# -lt 1 ]; then
    echo Usage: test_deadtime.sh IP
    exit 1
fi

server=$1

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh
. $incdir/common_test_fns.inc

failed=0

smbclient="$BINDIR/smbclient"
smbcontrol="$BINDIR/smbcontrol"

global_inject_conf=$(dirname $SMB_CONF_PATH)/global_inject.conf

echo "deadtime = 1" > $global_inject_conf
$smbcontrol smbd reload-config

cd $SELFTEST_TMPDIR || exit 1

# Create the smbclient communication pipes.
rm -f smbclient-stdin smbclient-stdout smbclient-stderr
mkfifo smbclient-stdin smbclient-stdout smbclient-stderr

export CLI_FORCE_INTERACTIVE=1
export SAMBA_DEPRECATED_SUPPRESS=1

# This gets inherited by smbclient and is required to smbclient doesn't get
# killed by an unhandled SIGPIPE when writing an SMB2 KEEPALIVE packet to the
# connection fd that was already closed by the server.
trap "" SIGPIPE

$smbclient //$server/tmp -U${USER}%${PASSWORD} \
	     < smbclient-stdin > smbclient-stdout 2>smbclient-stderr &
client_pid=$!

sleep 1

exec 100>smbclient-stdin  101<smbclient-stdout 102<smbclient-stderr

# consume the smbclient startup message
head -n 1 <&101

sleep 70

err=$(head -n 1 <&102)
echo "err: $err"

kill $client_pid

echo "$err" | grep NT_STATUS_CONNECTION_DISCONNECTED
testit "deadtime" test $? -eq 0 || failed=$(expr $failed + 1)

echo "" > $global_inject_conf
$smbcontrol smbd reload-config

rm -f smbclient-stdin smbclient-stdout smbclient-stderr

testok $0 $failed
