#!/bin/sh
#
# Check that replay-cache records in smbXsrv_open_global.tdb do not leak.
#
# The records are an index on the open records, keyed by the client GUID plus
# the create GUID, so they are the ones with a 32 byte key. Open records are
# keyed by a 4 byte id.
#
# Compare the set of keys around each torture test rather than counting them.
# Other tests in the same environment leave durable handles disconnected and
# waiting for the scavenger, so the database is not empty when we start, and
# those records can disappear while we run. Only a key that we added and that
# is still there afterwards is a leak.

if [ $# -lt 5 ]; then
	cat <<USAGE
Usage: test_replay_cache_records.sh SERVER_IP SHARE USERNAME PASSWORD LOCK_DIR
USAGE
	exit 1
fi

SERVER_IP="$1"
SHARE="$2"
USERNAME="$3"
PASSWORD="$4"
LOCK_DIR="$5"
shift 5

incdir=$(dirname "$0")/../../../testprogs/blackbox
. "$incdir"/subunit.sh

# smbtorture creates its per-run output directory below the current one unless
# it is told otherwise, so make sure we are somewhere writable.
cd "$SELFTEST_TMPDIR" || exit 1

failed=0

DB="$LOCK_DIR/smbXsrv_open_global.tdb"
TDBDUMP=tdbdump
if [ -x "$BINDIR/tdbdump" ]; then
	TDBDUMP="$BINDIR/tdbdump"
fi
BEFORE="$SELFTEST_TMPDIR/replay_cache_keys_before"
AFTER="$SELFTEST_TMPDIR/replay_cache_keys_after"

list_replay_keys()
{
	_dump=$("$TDBDUMP" "$DB") || return 1
	printf '%s\n' "$_dump" | grep '^key(32) =' | sort
}

# Wait for the keys we added to go away. The abandon test leaves its handles for
# the server to tear down, and that is not synchronised with smbtorture exiting.
# In practice the first check already passes, as the test reconnects and unlinks
# before it exits, so the retries are only here to keep a loaded machine from
# wrongly reporting a leak.
wait_for_keys_gone()
{
	_i=0

	while [ "$_i" -lt 5 ]; do
		list_replay_keys >"$AFTER" || return 1
		_new=$(comm -13 "$BEFORE" "$AFTER")
		if [ -z "$_new" ]; then
			return 0
		fi
		sleep 1
		_i=$((_i + 1))
	done

	echo "leaked $(echo "$_new" | wc -l) replay-cache records" \
		"after ${_i}s:"
	echo "$_new"
	return 1
}

run_and_check()
{
	_test="$1"

	list_replay_keys >"$BEFORE" || return 1

	$VALGRIND $BINDIR/smbtorture --basedir="$SELFTEST_TMPDIR" \
		"//$SERVER_IP/$SHARE" \
		-U"$USERNAME"%"$PASSWORD" "$_test" || return 1

	wait_for_keys_gone
}

testit "abandon" \
	run_and_check smb2.durable-v2-open.replay-cache-abandon ||
	failed=$((failed + 1))

testit "no_durable" \
	run_and_check smb2.durable-v2-open.replay-cache-no-durable ||
	failed=$((failed + 1))

testit "reconnect_v2" \
	run_and_check smb2.durable-v2-open.replay-cache-reconnect-v2 ||
	failed=$((failed + 1))

testit "reconnect_v1" \
	run_and_check smb2.durable-v2-open.replay-cache-reconnect-v1 ||
	failed=$((failed + 1))

testok "$0" "$failed"
