#!/usr/bin/env bash
#
# Test smbcontrol close-denied-share command.
#
# Copyright (C) 2020 Volker Lendecke

if [ $# -lt 6 ]; then
	echo Usage: test_close_denied_share.sh \
		SERVERCONFFILE SHARESEC SMBCLIENT SMBCONTROL IP SHARE
	exit 1
fi

CONF=$1
SHARESEC=$2
SMBCLIENT=$3
SMBCONTROL=$4
SERVER=$5
SHARE=$6

# Extract the actual config file path from $CONF
SERVERCONFFILE=$(echo "${CONF}" | sed 's/^--configfile=//')

incdir=$(dirname $0)/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

cd $SELFTEST_TMPDIR || exit 1

CONF_BACKUP=$(mktemp ./close-denied-share.conf.XXXXXX) || exit 1
cp -p -- "$SERVERCONFFILE" "$CONF_BACKUP" || exit 1

# Cleanup trap to restore configuration and reload smbd on exit
cleanup() {
	rc=$?
	cp -p -- "$CONF_BACKUP" "$SERVERCONFFILE" || exit 1
	${SMBCONTROL} ${CONF} all reload-config || exit 1
	rm -f -- "$CONF_BACKUP"
	exit "$rc"
}
trap cleanup EXIT

# Helper functions to cleanly restart client and FIFOs
start_client() {
	exec 100>&- || true
	exec 101<&- || true
	rm -f smbclient-stdin smbclient-stdout
	mkfifo smbclient-stdin smbclient-stdout
	${SMBCLIENT} //${SERVER}/${SHARE} ${CONF} -U${USER}%${PASSWORD} \
		<smbclient-stdin >smbclient-stdout &
	CLIENT_PID=$!
	sleep 1
	exec 100>smbclient-stdin 101<smbclient-stdout
	head -n 1 <&101
}

stop_client() {
	kill ${CLIENT_PID} 2>/dev/null || true
	exec 100>&- || true
	exec 101<&- || true
	rm -f smbclient-stdin smbclient-stdout
}

check_share_disconnected() {
	if [ "$COUNT" -eq 1 ]; then
		return 0
	fi

	printf 'Expected 1 NT_STATUS_NETWORK_NAME_DELETED response, got %s\n' \
		"$COUNT"
	return 1
}

CLI_FORCE_INTERACTIVE=1
export CLI_FORCE_INTERACTIVE

# --- Original Test: ACL deny ---
start_client

testit "smbcontrol" ${SMBCONTROL} ${CONF} smbd close-denied-share ${SHARE} ||
	failed=$(expr $failed + 1)
sleep 1

echo dir >&100

COUNT=$(head -n 2 <&101 |
	grep NT_STATUS_NETWORK_NAME_DELETED |
	wc -l)
testit "Verify close-denied-share did not kill valid client" \
	test $COUNT -eq 0 || failed=$(expr $failed + 1)

testit "Deny access" ${SHARESEC} ${CONF} --replace S-1-1-0:DENIED/0x0/FULL \
	${SHARE} || failed=$(expr $failed + 1)

testit "smbcontrol" ${SMBCONTROL} ${CONF} smbd close-denied-share ${SHARE} ||
	failed=$(expr $failed + 1)
sleep 1

echo dir >&100

COUNT=$(head -n 2 <&101 |
	grep NT_STATUS_NETWORK_NAME_DELETED |
	wc -l)
testit "Verify close-denied-share did kill now-invalid client" \
	test $COUNT -eq 1 || failed=$(expr $failed + 1)

stop_client

testit "Allow access" ${SHARESEC} ${CONF} --replace S-1-1-0:ALLOWED/0x0/FULL \
	${SHARE} || failed=$(expr $failed + 1)

# --- Test 1: Share-level hosts deny ---
start_client
sed -i "/^\[${SHARE}\]/a\\\thosts deny = ${SERVER}" "${SERVERCONFFILE}" ||
	exit 1
testit "reload-config for share hosts deny" \
	${SMBCONTROL} ${CONF} all reload-config ||
	failed=$(expr $failed + 1)
testit "smbcontrol close-denied-share share hosts deny" \
	${SMBCONTROL} ${CONF} smbd close-denied-share ${SHARE} ||
	failed=$(expr $failed + 1)
sleep 1
echo dir >&100
COUNT=$(head -n 2 <&101 | grep NT_STATUS_NETWORK_NAME_DELETED | wc -l)
testit "share_hosts_deny" check_share_disconnected ||
	failed=$(expr $failed + 1)
stop_client
cp -p -- "$CONF_BACKUP" "$SERVERCONFFILE" || exit 1

# --- Test 2: Global hosts deny, share allows ---
start_client
sed -i "/^\[global\]/a\\\thosts deny = ${SERVER}" "${SERVERCONFFILE}" ||
	exit 1
sed -i "/^\[${SHARE}\]/a\\\thosts allow = ${SERVER}" "${SERVERCONFFILE}" ||
	exit 1
testit "reload-config for global hosts deny" \
	${SMBCONTROL} ${CONF} all reload-config ||
	failed=$(expr $failed + 1)
testit "smbcontrol close-denied-share global hosts deny" \
	${SMBCONTROL} ${CONF} smbd close-denied-share ${SHARE} ||
	failed=$(expr $failed + 1)
sleep 1
echo dir >&100
COUNT=$(head -n 2 <&101 | grep NT_STATUS_NETWORK_NAME_DELETED | wc -l)
testit "global_hosts_deny" check_share_disconnected ||
	failed=$(expr $failed + 1)
stop_client

testok $0 $failed
