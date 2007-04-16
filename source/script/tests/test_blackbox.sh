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

plantest "blackbox.smbclient" dc $incdir/../../../testprogs/blackbox/test_smbclient.sh "\$NETBIOSNAME" "\$USERNAME" "\$PASSWORD" "\$DOMAIN" "$PREFIX" "$ADDARGS"
plantest "blackbox.kinit" dc $incdir/../../../testprogs/blackbox/test_kinit.sh "\$NETBIOSNAME" "\$USERNAME" "\$PASSWORD" "\$REALM" "$PREFIX" "$ADDARGS"

plantest "blackbox.cifsdd" dc $incdir/../../../testprogs/blackbox/test_cifsdd.sh "\$NETBIOSNAME" "\$USERNAME" "\$PASSWORD" "\$DOMAIN" "$ADDARGS"
