#!/bin/sh
#
# Blackbox tests for the rpcclient --pw-nt-hash option
#

if [ $# -lt 4 ]; then
cat <<EOF
Usage: test_rpcclient_pw_nt_hash.sh USERNAME PASSWORD SERVER RPCCLIENT
EOF
exit 1;
fi

USERNAME="$1"
PASSWORD="$2"
SERVER="$3"
RPCCLIENT="$4"

HASH=`echo -n $PASSWORD | iconv -t utf16le | openssl md4 |cut -d ' ' -f2`

RPCCLIENTCMD="$RPCCLIENT $SERVER --pw-nt-hash -U$USERNAME%$HASH -c queryuser"

incdir=$(dirname $0)/../../../testprogs/blackbox
. $incdir/subunit.sh

testit "rpcclient --pw-nt-hash" $RPCCLIENTCMD || failed=`expr $failed + 1`

testok $0 $failed
