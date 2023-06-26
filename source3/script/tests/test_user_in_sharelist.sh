#!/usr/bin/env bash

if [ $# -lt 2 ]; then
    echo Usage: $0 RPCCLIENT SERVER
    exit 1
fi

incdir=$(dirname $0)/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

RPCCLIENT="$1"; shift 1
SERVER="$1"; shift 1

"${RPCCLIENT}" "${SERVER}" -U"${USER}"%"${PASSWORD}" -c netshareenum |
    grep "^netname: $USER\$"
RC=$?
testit "Verify username is listed in netshareenum due to [homes]" \
       test $RC = 0 || failed=$((failed+1))

testok $0 $failed
