#!/bin/bash
#
# Test smbd handling when open returns EINTR
#
# Copyright (C) 2020 Volker Lendecke

if [ $# -lt 5 ]; then
    echo Usage: test_open_eintr.sh \
	 --configfile=SERVERCONFFILE SMBCLIENT SMBCONTROL SERVER SHARE
exit 1
fi

CONF=$1; shift 1
SMBCLIENT=$1; shift 1
SMBCONTROL=$1; shift 1
SERVER=$1; shift 1
SHARE=$1; shift 1

error_inject_conf=$(dirname ${SERVERCONFFILE})/error_inject.conf
> ${error_inject_conf}

incdir=$(dirname $0)/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

rm -f smbclient-stdin smbclient-stdout smbclient-stderr
mkfifo smbclient-stdin smbclient-stdout smbclient-stderr

CLI_FORCE_INTERACTIVE=1; export CLI_FORCE_INTERACTIVE

${SMBCLIENT} //${SERVER}/${SHARE} ${CONF} -U${USER}%${PASSWORD} \
	     < smbclient-stdin > smbclient-stdout 2>smbclient-stderr &
CLIENT_PID=$!

sleep 1

exec 100>smbclient-stdin 101<smbclient-stdout 102<smbclient-stderr

# consume the smbclient startup messages
head -n 1 <&101
head -n 1 <&102

echo "error_inject:openat = EINTR" > ${error_inject_conf}
${SMBCONTROL} ${CONF} 0 reload-config

sleep 1
> ${error_inject_conf}

echo 'get badnames/blank.txt -' >&100

sleep 1

> ${error_inject_conf}
${SMBCONTROL} ${CONF} 0 reload-config

head -n 1 <&102 | grep 'getting file' > /dev/null
GREP_RET=$?

kill ${CLIENT_PID}
rm -f smbclient-stdin smbclient-stdout smbclient-stderr

testit "Verify that we could get the file" \
       test $GREP_RET -eq 0 || failed=$(expr $failed + 1)

testok $0 $failed
