#!/bin/sh

# this runs tests that interact directly with the command-line tools rather than using the API

if [ $# -lt 5 ]; then
cat <<EOF
Usage: test_blackbox.sh SERVER USERNAME PASSWORD DOMAIN PREFIX [...]
EOF
exit 1;
fi

SERVER=$1
USERNAME=$2
PASSWORD=$3
DOMAIN=$4
PREFIX=$5
shift 5
ADDARGS="$@"

incdir=`dirname $0`
. $incdir/test_functions.sh

# skip the smbclient test until jelmer can work on it. Right now the
# test makes no sense at all with the new test system (tridge) testit
# "smbclient" $incdir/../../../testprogs/blackbox/test_smbclient.sh "$SERVER" "$USERNAME" "$PASSWORD" "$DOMAIN" "$PREFIX" "$ADDARGS"
testit "cifsdd" $incdir/../../../testprogs/blackbox/test_cifsdd.sh "$SERVER" "$USERNAME" "$PASSWORD" "$DOMAIN" "$ADDARGS"

testok $0 $failed
