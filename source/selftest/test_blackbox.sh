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

bbdir=$incdir/../../testprogs/blackbox

plantest "blackbox.smbclient" dc $bbdir/test_smbclient.sh "\$SERVER" "\$USERNAME" "\$PASSWORD" "\$DOMAIN" "$PREFIX" "$ADDARGS"
plantest "blackbox.kinit" dc $bbdir/test_kinit.sh "\$SERVER" "\$USERNAME" "\$PASSWORD" "\$REALM" "\$DOMAIN" "$PREFIX" "$ADDARGS"
plantest "blackbox.cifsdd" dc $bbdir/test_cifsdd.sh "\$SERVER" "\$USERNAME" "\$PASSWORD" "\$DOMAIN" "$ADDARGS"
plantest "blackbox.nmblookup:dc" dc $bbdir/test_nmblookup.sh "\$NETBIOSNAME" "\$NETBIOSALIAS" "\$SERVER" "\$SERVER_IP" $ADDARGS
plantest "blackbox.nmblookup:member" member $bbdir/test_nmblookup.sh "\$NETBIOSNAME" "\$NETBIOSALIAS" "\$SERVER" "\$SERVER_IP" $ADDARGS
