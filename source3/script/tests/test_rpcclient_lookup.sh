#!/bin/sh
#
# Blackbox tests for the rpcclient LSA lookup commands
#
# Copyright (C) 2020 Christof Schmitt

if [ $# -lt 4 ]; then
cat <<EOF
Usage: test_net_srvsvc.sh USERNAME PASSWORD SERVER RPCCLIENT
EOF
exit 1;
fi

USERNAME="$1"
PASSWORD="$2"
SERVER="$3"
RPCCLIENT="$4"

RPCCLIENTCMD="$RPCCLIENT $SERVER -U$USERNAME%$PASSWORD"

incdir=$(dirname $0)/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

$RPCCLIENTCMD -c "lookupsids S-1-1-0"
RC=$?
testit "lookupsids" test $RC -eq 0 || failed=$(expr $failed + 1)

$RPCCLIENTCMD -c "lookupsids_level 1 S-1-1-0"
RC=$?
testit "lookupsids_level" test $RC -eq 0 || failed=$(expr $failed + 1)

$RPCCLIENTCMD -c "lookupnames Everyone"
RC=$?
testit "lookupnames" test $RC -eq 0 || failed=$(expr $failed + 1)

$RPCCLIENTCMD -c "lookupnames_level 1 Everyone"
RC=$?
testit "lookupnames_level" test $RC -eq 0 || failed=$(expr $failed + 1)

testok $0 $failed
