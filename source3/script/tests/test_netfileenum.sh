#!/bin/bash
#
# Test rpcclient netfileenum
#
# Copyright (C) 2020 Volker Lendecke

if [ $# -lt 5 ]; then
    echo Usage: $0 \
	 SMBCLIENT RPCCLIENT NET SERVER SHARE
exit 1
fi

SMBCLIENT="$1"; shift 1
RPCCLIENT="$1"; shift 1
NET="$1"; shift 1
SERVER="$1"; shift 1
SHARE="$1"; shift 1

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

FILE=x64

printf "open %s\\n" "$FILE" >&100

sleep 1

testit "Create builtin\\administrators group" \
       "${NET}" groupmap add \
       sid=S-1-5-32-544 unixgroup="${USER}"-group type=builtin || \
    failed=$((failed+1))
testit "Add ${USER} to builtin\\administrators" \
       "${NET}" groupmap addmem S-1-5-32-544 \
       $("${NET}" lookup name "${USER}" | cut -d' ' -f1) || \
    failed=$((failed+1))

"${RPCCLIENT}" "${SERVER}" -U"${USER}"%"${PASSWORD}" -c netfileenum |
    grep "$FILE"\$
RC=$?
testit "netfileenum" test $RC = 0 || failed=$((failed+1))

kill ${CLIENT_PID}
rm -f smbclient-stdin smbclient-stdout smbclient-stderr

testit "Remove ${USER} from builtin\\administrators" \
       "${NET}" groupmap delmem S-1-5-32-544 \
       $("${NET}" lookup name "${USER}" | cut -d' ' -f1) || \
    failed=$((failed+1))
testit "Remove builtin\\administrators group" \
       "${NET}" groupmap delete \
       sid=S-1-5-32-544 || \
    failed=$((failed+1))

testok $0 $failed
