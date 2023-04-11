#!/bin/bash
#
# Test smbd let cluster node 0 destroy the connection,
# if the client with a specific client-guid connections to node 1
#

if [ $# -lt 4 ]; then
	echo Usage: test_smbXsrv_client_cross_node.sh SERVERCONFFILE NODE0 NODE1 SHARENAME
	exit 1
fi

CONF=$1
NODE0=$2
NODE1=$3
SHARE=$4

SMBCLIENT="$BINDIR/smbclient"
SMBSTATUS="$BINDIR/smbstatus"

incdir=$(dirname "$0")/../../../testprogs/blackbox
. "$incdir"/subunit.sh

failed=0

test_smbclient()
{
	name="$1"
	server="$2"
	share="$3"
	cmd="$4"
	shift
	shift
	subunit_start_test "$name"
	output=$($VALGRIND $SMBCLIENT //$server/$share -c "$cmd" "$@" 2>&1)
	status=$?
	if [ x$status = x0 ]; then
		subunit_pass_test "$name"
	else
		echo "$output" | subunit_fail_test "$name"
	fi
	return $status
}

cd "$SELFTEST_TMPDIR" || exit 1

# Create the smbclient communication pipes.
rm -f smbclient-stdin smbclient-stdout smbclient-stderr
mkfifo smbclient-stdin smbclient-stdout smbclient-stderr

smbstatus_num_sessions()
{
	UID_WRAPPER_INITIAL_RUID=0 UID_WRAPPER_INITIAL_EUID=0 "$SMBSTATUS" "$CONF" --json | jq -M '.sessions | length'
}

testit_grep "step1: smbstatus 0 sessions" '^0$' smbstatus_num_sessions || failed=$(expr $failed + 1)

test_smbclient "smbclient against node0[${NODE0}]" "${NODE0}" "${SHARE}" "ls" -U"${DC_USERNAME}"%"${DC_PASSWORD}" \
	--option="libsmb:client_guid=6112f7d3-9528-4a2a-8861-0ca129aae6c4" \
	|| failed=$(expr $failed + 1)

testit_grep "step2: smbstatus 0 sessions" '^0$' smbstatus_num_sessions || failed=$(expr $failed + 1)

CLI_FORCE_INTERACTIVE=1
export CLI_FORCE_INTERACTIVE

testit "start backgroup smbclient against node0[${NODE0}]" true || failed=$(expr $failed + 1)

# Connect a first time
${SMBCLIENT} //"${NODE0}"/"${SHARE}" -U"${DC_USERNAME}"%"${DC_PASSWORD}" \
	--option="libsmb:client_guid=6112f7d3-9528-4a2a-8861-0ca129aae6c4" \
	<smbclient-stdin >smbclient-stdout 2>smbclient-stderr &
CLIENT_PID=$!

exec 100>smbclient-stdin 101<smbclient-stdout 102<smbclient-stderr

testit "sleep 1 second" true || failed=$(expr $failed + 1)
sleep 1

testit_grep "step3: smbstatus 1 session" '^1$' smbstatus_num_sessions || failed=$(expr $failed + 1)

# Connect a second time
unset CLI_FORCE_INTERACTIVE
test_smbclient "smbclient against node1[${NODE1}]" "${NODE1}" "${SHARE}" "ls" -U"${DC_USERNAME}"%"${DC_PASSWORD}" \
	--option="libsmb:client_guid=6112f7d3-9528-4a2a-8861-0ca129aae6c4" \
	|| failed=$(expr $failed + 1)

kill $CLIENT_PID
rm -f smbclient-stdin smbclient-stdout smbclient-stderr

testit_grep "step24: smbstatus 0 sessions" '^0$' smbstatus_num_sessions || failed=$(expr $failed + 1)

testok "$0" "$failed"
