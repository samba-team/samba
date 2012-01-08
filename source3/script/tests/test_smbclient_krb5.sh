#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: test_smbclient.sh ccache smbclient3 server <smbclient args>
EOF
exit 1;
fi

KRB5CCNAME=$1
export KRB5CCNAME
SMBCLIENT3=$2
SERVER=$3
shift 3
ADDARGS="$*"

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh
testit "smbclient" $VALGRIND $SMBCLIENT3 //$SERVER/tmp -c 'ls' -k $ADDARGS || failed=`expr $failed + 1`

testok $0 $failed
