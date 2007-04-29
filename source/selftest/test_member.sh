#!/bin/sh

incdir=`dirname $0`
. $incdir/test_functions.sh

plantest "RPC-ECHO against member server" member $VALGRIND bin/smbtorture $TORTURE_OPTIONS ncacn_np:"\$SERVER" -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN RPC-ECHO "$*"
