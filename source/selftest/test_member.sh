#!/bin/sh

incdir=`dirname $0`
. $incdir/test_functions.sh

plantest "RPC-ECHO against member server with local creds" member $VALGRIND $samba4bindir/smbtorture $TORTURE_OPTIONS ncacn_np:"\$NETBIOSNAME" -U"\$NETBIOSNAME/\$USERNAME"%"\$PASSWORD" RPC-ECHO "$*"
plantest "RPC-ECHO against member server with domain creds" member $VALGRIND $samba4bindir/smbtorture $TORTURE_OPTIONS ncacn_np:"\$NETBIOSNAME" -U"\$DOMAIN/\$DC_USERNAME"%"\$DC_PASSWORD" RPC-ECHO "$*"
plantest "RPC-SAMR against member server with local creds" member $VALGRIND $samba4bindir/smbtorture $TORTURE_OPTIONS ncacn_np:"\$NETBIOSNAME" -U"\$NETBIOSNAME/\$USERNAME"%"\$PASSWORD" "RPC-SAMR" "$*"
plantest "RPC-SAMR-USERS against member server with local creds" member $VALGRIND $samba4bindir/smbtorture $TORTURE_OPTIONS ncacn_np:"\$NETBIOSNAME" -U"\$NETBIOSNAME/\$USERNAME"%"\$PASSWORD" "RPC-SAMR-USERS" "$*"
plantest "RPC-SAMR-PASSWORDS against member server with local creds" member $VALGRIND $samba4bindir/smbtorture $TORTURE_OPTIONS ncacn_np:"\$NETBIOSNAME" -U"\$NETBIOSNAME/\$USERNAME"%"\$PASSWORD" "RPC-SAMR-PASSWORDS" "$*"
plantest "wbinfo -a against member server with domain creds" member $VALGRIND $samba4bindir/wbinfo -a "\$DOMAIN/\$DC_USERNAME"%"\$DC_PASSWORD"
