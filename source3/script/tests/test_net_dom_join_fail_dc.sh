#!/bin/sh

if [ $# -lt 4 ]; then
cat <<EOF
Usage: test_net_dom_join_fail_dc.sh  USERNAME PASSWORD DOMAIN PREFIX
EOF
exit 1;
fi

DC_USERNAME="$1"
DC_PASSWORD="$2"
DOMAIN="$3"
PREFIX="$4"
shift 4
ADDARGS="$*"

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh
mkdir -p $PREFIX/private
testit_expect_failure "net_dom_join_fail_dc" $VALGRIND $BINDIR/net dom join domain=$DOMAIN account=$USERNAME password=$PASSWORD --option=netbiosname=netrpcjointest --option=domainlogons=yes --option=privatedir=$PREFIX/private $ADDARGS || failed=`expr $failed + 1`

testok $0 $failed
