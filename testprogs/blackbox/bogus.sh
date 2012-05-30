#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: blackbox_newuser.sh PREFIX
EOF
exit 1;
fi

. `dirname $0`/subunit.sh

SERVER=$1
SHARE=$2
USER=$3
PWD=$4
DC_USER=$5
DC_PWD=$6
smbclient=$7
shift 7

TEST_USER=bogus_testuser
TEST_PWD=bogus_pass3#@
net="$BINDIR/net"
testit_expect_failure "smbclient" $smbclient "//$SERVER/$SHARE" -W POUET -U$DC_USER%$DC_PWD -c "dir"&& failed=`expr $failed + 1`
testit "net.user.add" $net rpc user add $TEST_USER $TEST_PWD -W $SERVER -U$SERVER\\$USER%$PWD -S $SERVER
testit "smbclient" $smbclient "//$SERVER/$SHARE" -W POUET -U$TEST_USER%$TEST_PWD -c "dir"|| failed=`expr $failed + 1`
testit "net.user.delete" $net rpc user delete $TEST_USER -W $SERVER -U$SERVER\\$USER%$PWD -S $SERVER
exit $failed
