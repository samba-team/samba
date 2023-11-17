#!/usr/bin/env bash
#
# Test smbd let cleanup registered ip addresses in a multichannel
# scenario
#

if [ $# -lt 3 ]; then
	echo Usage: test_smbXsrv_client_ctdb_registered_ips.sh SERVERCONFFILE CTDB_IFACE_IP SHARENAME
	exit 1
fi

CONF=$1
CTDB_IFACE_IP=$2
SHARE=$3

SMBCLIENT="$BINDIR/smbclient"
SMBSTATUS="$BINDIR/smbstatus"
CTDB="$BINDIR/ctdb"
TIMELIMIT="$BINDIR/timelimit"

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
rm -f smbclient1-stdin smbclient1-stdout smbclient1-stderr
mkfifo smbclient1-stdin smbclient1-stdout smbclient1-stderr
rm -f smbclient2-stdin smbclient2-stdout smbclient2-stderr
mkfifo smbclient2-stdin smbclient2-stdout smbclient2-stderr

smbstatus_num_sessions()
{
	# We don't check for died processes
	UID_WRAPPER_INITIAL_RUID=0 UID_WRAPPER_INITIAL_EUID=0 "$SMBSTATUS" "$CONF" --fast --json | jq -M '.sessions | length'
}

ctdb_add_public_ip()
{
	UID_WRAPPER_INITIAL_RUID=0 UID_WRAPPER_INITIAL_EUID=0 "$CTDB" addip ${CTDB_IFACE_IP}/24 lo
	UID_WRAPPER_INITIAL_RUID=0 UID_WRAPPER_INITIAL_EUID=0 "$CTDB" ipreallocate
}

ctdb_ip()
{
	UID_WRAPPER_INITIAL_RUID=0 UID_WRAPPER_INITIAL_EUID=0 "$CTDB" ip
}

ctdb_gettickles()
{
	UID_WRAPPER_INITIAL_RUID=0 UID_WRAPPER_INITIAL_EUID=0 "$CTDB" gettickles ${CTDB_IFACE_IP}
}

ctdb_reload_public_ips()
{
	UID_WRAPPER_INITIAL_RUID=0 UID_WRAPPER_INITIAL_EUID=0 "$CTDB" reloadips 0
	UID_WRAPPER_INITIAL_RUID=0 UID_WRAPPER_INITIAL_EUID=0 "$CTDB" ipreallocate
}

testit_grep_count "step1: smbstatus 0 sessions" '^0$' 1 smbstatus_num_sessions || failed=$(expr $failed + 1)

test_smbclient "step2: smbclient against node0[${CTDB_IFACE_IP}]" "${CTDB_IFACE_IP}" "${SHARE}" "ls" -U"${DC_USERNAME}"%"${DC_PASSWORD}" \
	--option="libsmb:client_guid=6112f7d3-9528-4a2a-8861-0ca129aae6c4" \
	|| failed=$(expr $failed + 1)

testit_grep_count "step2: smbstatus 0 sessions" '^0$' 1 smbstatus_num_sessions || failed=$(expr $failed + 1)

CLI_FORCE_INTERACTIVE=1
export CLI_FORCE_INTERACTIVE

testit "step3: start backgroup smbclient against node0[${CTDB_IFACE_IP}]" true || failed=$(expr $failed + 1)

# Connect a first time
${SMBCLIENT} //"${CTDB_IFACE_IP}"/"${SHARE}" -U"${DC_USERNAME}"%"${DC_PASSWORD}" \
	--option="libsmb:client_guid=6112f7d3-9528-4a2a-8861-0ca129aae6c4" \
	<smbclient1-stdin >smbclient1-stdout 2>smbclient1-stderr &
CLIENT1_PID=$!

exec 100>smbclient1-stdin 101<smbclient1-stdout 102<smbclient1-stderr

testit_grep_count "step3: smbclient1-stdout" 'Try "help" to get a list of possible commands.' 1 $TIMELIMIT 15 head -1 smbclient1-stdout || failed=$(expr $failed + 1)

testit_grep_count "step3: smbstatus 1 session" '^1$' 1 smbstatus_num_sessions || failed=$(expr $failed + 1)

testit_grep_count "step3: ctdb_ip" "${CTDB_IFACE_IP}" 0 ctdb_ip || failed=$(expr $failed + 1)
testit_expect_failure_grep "step3: ctdb_gettickles" "Control GET_TCP_TICKLE_LIST failed" ctdb_gettickles || failed=$(expr $failed + 1)

testit "step4: ctdb_add_public_ip" ctdb_add_public_ip || failed=$(expr $failed + 1)

testit_grep_count "step4: ctdb_ip" "^${CTDB_IFACE_IP} 0\$" 1 ctdb_ip || failed=$(expr $failed + 1)
testit_grep_count "step4: ctdb_gettickles" "Num connections: 0" 1 ctdb_gettickles || failed=$(expr $failed + 1)

testit "step5: start backgroup 2nd smbclient against node0[${CTDB_IFACE_IP}]" true || failed=$(expr $failed + 1)
# Connect a second time
${SMBCLIENT} //"${CTDB_IFACE_IP}"/"${SHARE}" -U"${DC_USERNAME}"%"${DC_PASSWORD}" \
	--option="libsmb:client_guid=6112f7d3-9528-4a2a-8861-0ca129aae6c4" \
	<smbclient2-stdin >smbclient2-stdout 2>smbclient2-stderr &
CLIENT2_PID=$!

exec 200>smbclient2-stdin 201<smbclient2-stdout 202<smbclient2-stderr

testit_grep_count "step5: smbclient2-stdout" 'Try "help" to get a list of possible commands.' 1 $TIMELIMIT 15 head -1 smbclient2-stdout || failed=$(expr $failed + 1)

testit_grep_count "step5: smbstatus 2 session" '^2$' 1 smbstatus_num_sessions || failed=$(expr $failed + 1)

# Only one connection was registered with the public address
testit_grep_count "step5: ctdb_ip" "^${CTDB_IFACE_IP} 0\$" 1 ctdb_ip || failed=$(expr $failed + 1)
testit_grep_count "step5: ctdb_gettickles NUM" "Num connections: 1" 1 ctdb_gettickles || failed=$(expr $failed + 1)
testit_grep_count "step5: ctdb_gettickles DST" "DST: ${CTDB_IFACE_IP}" 1 ctdb_gettickles || failed=$(expr $failed + 1)

unset CLI_FORCE_INTERACTIVE

kill $CLIENT1_PID
rm -f smbclient1-stdin smbclient1-stdout smbclient1-stderr

testit "step6: sleep 1 second" true || failed=$(expr $failed + 1)
sleep 1

testit_grep_count "step6: smbstatus 1 session" '^1$' 1 smbstatus_num_sessions || failed=$(expr $failed + 1)

testit_grep_count "step6: ctdb_ip" "^${CTDB_IFACE_IP} 0\$" 1 ctdb_ip || failed=$(expr $failed + 1)
testit_grep_count "step6: ctdb_gettickles NUM" "Num connections: 1" 1 ctdb_gettickles || failed=$(expr $failed + 1)
testit_grep_count "step6: ctdb_gettickles DST" "DST: ${CTDB_IFACE_IP}" 1 ctdb_gettickles || failed=$(expr $failed + 1)

testit "step7: ctdb_reload_public_ips" ctdb_reload_public_ips || failed=$(expr $failed + 1)

testit_grep_count "step7: ctdb_ip" "${CTDB_IFACE_IP}" 0 ctdb_ip || failed=$(expr $failed + 1)
testit_expect_failure_grep "step3: ctdb_gettickles" "Control GET_TCP_TICKLE_LIST failed" ctdb_gettickles || failed=$(expr $failed + 1)

testit "step7: sleep 2 second" true || failed=$(expr $failed + 1)
sleep 2

testit_grep_count "step7: smbstatus 0 sessions" '^0$' 1 smbstatus_num_sessions || failed=$(expr $failed + 1)

kill $CLIENT2_PID
rm -f smbclient2-stdin smbclient2-stdout smbclient2-stderr

testok "$0" "$failed"
