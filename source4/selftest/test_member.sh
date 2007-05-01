#!/bin/sh

incdir=`dirname $0`
. $incdir/test_functions.sh

plantest "RPC-ECHO against member server with local creds" member $VALGRIND bin/smbtorture $TORTURE_OPTIONS ncacn_np:"\$NETBIOSNAME" -U"\$NETBIOSNAME\\\\\$USERNAME"%"\$PASSWORD" RPC-ECHO "$*"
plantest "RPC-ECHO against member server with domain creds" member $VALGRIND bin/smbtorture $TORTURE_OPTIONS ncacn_np:"\$NETBIOSNAME" -U"\$DOMAIN\\\\\$DC_USERNAME"%"\$DC_PASSWORD" RPC-ECHO "$*"
