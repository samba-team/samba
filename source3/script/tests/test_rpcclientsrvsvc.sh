#!/bin/sh
#
# Blackbox tests for the rpcclient srvsvc commands
#
# Copyright (C) 2015 Christof Schmitt

if [ $# -lt 5 ]; then
cat <<EOF
Usage: test_net_srvsvc.sh USERNAME PASSWORD SERVER RPCCLIENT SHARE1
EOF
exit 1;
fi

USERNAME="$1"
PASSWORD="$2"
SERVER="$3"
RPCCLIENT="$4"
SHARE1="$5"

RPCCLIENTCMD="$RPCCLIENT $SERVER -U$USERNAME%$PASSWORD"

SHARENAME=SRVSVCTEST
MAX_USERS=5
COMMENT="share for RPC SRVSVC testing"

incdir=$(dirname $0)/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

# Query path from existing share

$RPCCLIENTCMD -c "netsharegetinfo $SHARE1"
RC=$?
testit "getinfo on S$SHARE1" test $RC = 0 || failed=$(expr $failed + 1)

SHAREPATH=$($RPCCLIENTCMD -c "netsharegetinfo '$SHARE1'" | \
	grep path: | sed -e 's/.*path:\t//')
testit "verifying $SHARE1 path" test -n  "$SHAREPATH" || \
	failed=$(expr $failed + 1)

# Add a new share

$RPCCLIENTCMD -c "netshareadd '$SHAREPATH' '$SHARENAME' '$MAX_USERS' '$COMMENT'"
RC=$?
testit "netshareadd" test $RC = 0 ||  failed=$(expr $failed + 1)

# Verify comment for new share

COMMENT_RET=$($RPCCLIENTCMD -c "netsharegetinfo '$SHARENAME'" | \
	grep remark: | sed -e 's/.*remark:\t//')

test "$COMMENT" = "$COMMENT_RET"
RC=$?
testit "verifying comment" test $RC -eq 0 || failed=$(expr $failed + 1)

# Verify share path for new share

SHAREPATH_RET=$($RPCCLIENTCMD -c "netsharegetinfo '$SHARENAME'" | \
	grep path: | sed -e 's/.*path:\t//')
test "$SHAREPATH" = "$SHAREPATH_RET"
RC=$?
testit "verifying share path" test $RC -eq 0 || failed=$(expr $failed + 1)

# Set CSC policy

$RPCCLIENTCMD -c "netsharesetdfsflags '$SHARENAME' 0x30"
RC=$?
testit "set csc policy" test $RC -eq 0 ||  failed=$(expr $failed + 1)

# Query CSC policy

CSC_CACHING_RET=$($RPCCLIENTCMD -c "netsharegetinfo '$SHARENAME' 1005" | \
	grep 'csc caching' | sed -e 's/.*csc caching: //')
testit "verifying csc policy" test $CSC_CACHING_RET -eq 3 || \
	failed=$(expr $failed + 1)

# Delete share

$RPCCLIENTCMD -c "netsharedel '$SHARENAME'"
RC=$?
testit "deleting share" test $RC -eq 0 || failed=$(expr $failed + 1)

# Verify that query to deleted share fails

$RPCCLIENTCMD -c "netsharegetinfo '$SHARENAME' 1005"
RC=$?
testit "querying deleted share" test $RC -eq 1 ||  failed=$(expr $failed + 1)

testok $0 $failed