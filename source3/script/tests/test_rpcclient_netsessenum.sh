#!/bin/sh
#
# Blackbox tests for the rpcclient srvsvc commands
#
# Copyright (C) 2018 Christof Schmitt

if [ $# -lt 6 ]; then
cat <<EOF
Usage: $0 DOMAIN ADMIN_USER ADMIN_PASSWORD SERVER RPCCLIENT SMBTORTURE3 SHARE
EOF
exit 1;
fi

DOMAIN="$1"
ADMIN_USER="$2"
ADMIN_PASSWORD="$3"
SERVER="$4"
RPCCLIENT="$5"
SMBTORTURE3="$6"
SHARE="$7"

USERPASS="-U$DOMAIN/$ADMIN_USER%$ADMIN_PASSWORD"
RPCCLIENTCMD="$RPCCLIENT $SERVER $USERPASS"

incdir=$(dirname $0)/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

#
# Verify initial number of sessions.
#
$RPCCLIENTCMD -c NetSessEnum | grep Received
RC=$?
testit "netsessenum" test $RC = 0 || failed=$(expr $failed + 1)

OUT=$($RPCCLIENTCMD -c NetSessEnum | grep Received)
test "$OUT" = "Received 1 entries."
RC=$?
testit "count1" test $RC -eq 0  || failed=$(expr $failed + 1)

#
# Inject smbd crash
#
$SMBTORTURE3 //"$SERVER"/"$SHARE" "$USERPASS" CLEANUP1

#
# Verify number of sessions after crash
#
OUT=$($RPCCLIENTCMD -c NetSessEnum | grep Received)
test "$OUT" = "Received 1 entries."
RC=$?
testit "count2" test $RC -eq 0  || failed=$(expr $failed + 1)

testok $0 $failed
