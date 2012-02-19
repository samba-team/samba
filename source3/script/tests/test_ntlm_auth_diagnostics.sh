#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: test_ntlm_auth_diagnostics.sh NTLM_AUTH DOMAIN USERNAME PASSWORD
EOF
exit 1;
fi

NTLM_AUTH=$1
DOMAIN=$2
USERNAME=$3
PASSWORD=$4
shift 4

ADDARGS="$*"

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

testit "ntlm_auth" $VALGRIND $NTLM_AUTH --domain=$DOMAIN --username=$USERNAME --password=$PASSWORD --diagnostics $ADDARGS || failed=`expr $failed + 1`

testok $0 $failed
