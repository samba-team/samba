#!/bin/bash
#
# Test smbcontrol close-denied-share command.
#
# Verify that changing and querying the security descriptor works. Also
# ensure that the output format for ACL entries does not change.
#
# The test uses well-known SIDs to not require looking up names and SIDs
#
# Copyright (C) 2015, 2019 Christof Schmitt

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

incdir=$(dirname $0)/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

rm -f smbclient-stdin smbclient-stdout
mkfifo smbclient-stdin smbclient-stdout

CLI_FORCE_INTERACTIVE=1; export CLI_FORCE_INTERACTIVE

${SMBCLIENT} //${SERVER}/${SHARE} ${CONF} -U${USER}%${PASSWORD} \
	     < smbclient-stdin > smbclient-stdout &
CLIENT_PID=$!

sleep 1

exec 100>smbclient-stdin  101<smbclient-stdout

# consume the smbclient startup message

head -n 1 <&101

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

kill ${CLIENT_PID}
rm -f smbclient-stdin smbclient-stdout

testit "Allow access" ${SHARESEC} ${CONF} --replace S-1-1-0:ALLOWED/0x0/FULL \
       ${SHARE} || failed=$(expr $failed + 1)

testok $0 $failed
