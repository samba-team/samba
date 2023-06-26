#!/usr/bin/env bash
#
# Test smbd doesn't crash if there an existing dead record for a client with a
# specific client-guid in smbXsrv_client_global.tdb
#

if [ $# -lt 2 ]; then
	echo Usage: test_smbXsrv_client_dead_rec.sh SERVERCONFFILE IP SHARENAME
	exit 1
fi

CONF=$1
SERVER=$2
SHARE=$3

SMBCLIENT="$BINDIR/smbclient"
SMBSTATUS="$BINDIR/smbstatus"

SMBD_LOG_FILE="$SMBD_TEST_LOG"
if [ -n "$SMBD_DONT_LOG_STDOUT" ]; then
	SMBD_LOG_FILE=$(dirname "$SMBD_TEST_LOG")/logs/log.smbd
fi
SMBD_LOG_FILE=$(realpath "$SMBD_LOG_FILE")

incdir=$(dirname "$0")/../../../testprogs/blackbox
. "$incdir"/subunit.sh

failed=0

cd "$SELFTEST_TMPDIR" || exit 1

#
# Note if we already have any panics in the smbd log.
#
panic_count_0=$(grep -c PANIC "$SMBD_LOG_FILE")

# Create the smbclient communication pipes.
rm -f smbclient-stdin smbclient-stdout smbclient-stderr
mkfifo smbclient-stdin smbclient-stdout smbclient-stderr

CLI_FORCE_INTERACTIVE=1
export CLI_FORCE_INTERACTIVE

# Connect a first time
${SMBCLIENT} //"${SERVER}"/"${SHARE}" -U"${USER}"%"${PASSWORD}" \
	--option="libsmb:client_guid=6112f7d3-9528-4a2a-8861-0ca129aae6c4" \
	<smbclient-stdin >smbclient-stdout 2>smbclient-stderr &
CLIENT_PID=$!

exec 100>smbclient-stdin 101<smbclient-stdout 102<smbclient-stderr

SMBD_PID=$(UID_WRAPPER_INITIAL_RUID=0 UID_WRAPPER_INITIAL_EUID=0 "$SMBSTATUS" -p "$CONF" | awk '/^[0-9]+/ {print $1}' | sort -u)

# Kill the first connection, leaves dead record in smbXsrv_client_global.tdb
kill -KILL "$SMBD_PID"
kill $CLIENT_PID

# Connect a second time
unset CLI_FORCE_INTERACTIVE
${SMBCLIENT} //"${SERVER}"/"${SHARE}" -U"${USER}"%"${PASSWORD}" \
	--option="libsmb:client_guid=6112f7d3-9528-4a2a-8861-0ca129aae6c4" \
	-c exit

rm -f smbclient-stdin smbclient-stdout smbclient-stderr

#
# Ensure the panic count didn't change.
#
# BUG: https://bugzilla.samba.org/show_bug.cgi?id=14882
#
panic_count_1=$(grep -c PANIC "$SMBD_LOG_FILE")

testit "check_panic" test "$panic_count_0" -eq "$panic_count_1" ||
	failed=$(expr $failed + 1)

testok "$0" "$failed"
