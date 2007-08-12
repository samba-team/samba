#!/bin/sh

# this runs tests that interact directly with the command-line tools rather than using the API

if [ $# -lt 1 ]; then
cat <<EOF
Usage: test_blackbox.sh PREFIX [...]
EOF
exit 1;
fi

PREFIX=$1
shift 1
ADDARGS="$*"

incdir=`dirname $0`
. $incdir/test_functions.sh

plantest "blackbox.smbclient" dc $incdir/../../testprogs/blackbox/test_smbclient.sh "\$SERVER" "\$USERNAME" "\$PASSWORD" "\$DOMAIN" "$PREFIX" "$ADDARGS"
plantest "blackbox.kinit" dc $incdir/../../testprogs/blackbox/test_kinit.sh "\$SERVER" "\$USERNAME" "\$PASSWORD" "\$REALM" "\$DOMAIN" "$PREFIX" "$ADDARGS"
plantest "blackbox.cifsdd" dc $incdir/../../testprogs/blackbox/test_cifsdd.sh "\$SERVER" "\$USERNAME" "\$PASSWORD" "\$DOMAIN" "$ADDARGS"
