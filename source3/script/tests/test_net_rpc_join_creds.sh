#!/bin/sh

if [ $# -lt 5 ]; then
cat <<EOF
Usage: test_net_rpc_join_creds.sh  DOMAIN USERNAME PASSWORD SERVER PREFIX
EOF
exit 1;
fi

DOMAIN="$1"
USERNAME="$2"
PASSWORD="$3"
SERVER="$4"
PREFIX="$5"
shift 5
ADDARGS="$*"

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh
mkdir -p $PREFIX/private
# Test using a credentials file.
credsfile=$PREFIX/creds.$$
printf '%s\n' "username=$USERNAME" "password=$PASSWORD" "domain=$DOMAIN" > "$credsfile"
testit "net_rpc_join_creds" $VALGRIND $BINDIR/net rpc join -S $SERVER --option=netbiosname=netrpcjointest --option=domainlogons=yes --option=privatedir=$PREFIX/private -A"$credsfile" $ADDARGS || failed=`expr $failed + 1`
testit "net_rpc_testjoin_creds" $VALGRIND $BINDIR/net rpc testjoin -S $SERVER --option=netbiosname=netrpcjointest --option=domainlogons=yes --option=privatedir=$PREFIX/private $ADDARGS || failed=`expr $failed + 1`
testit "net_rpc_changetrustpw_creds" $VALGRIND $BINDIR/net rpc changetrustpw -S $SERVER --option=netbiosname=netrpcjointest --option=domainlogons=yes --option=privatedir=$PREFIX/private $ADDARGS || failed=`expr $failed + 1`
testit "net_rpc_testjoin2_creds" $VALGRIND $BINDIR/net rpc testjoin -S $SERVER --option=netbiosname=netrpcjointest --option=domainlogons=yes --option=privatedir=$PREFIX/private $ADDARGS || failed=`expr $failed + 1`
rm -f $credsfile

testok $0 $failed
