#!/bin/sh

# add tests to this list as they start passing, so we test
# that they stay passing
ncacn_np_tests="RPC-ECHO"

incdir=`dirname $0`
. $incdir/test_functions.sh

plantest "RPC-ECHO against member server" member $VALGRIND bin/smbtorture $TORTURE_OPTIONS ncacn_np:"\$SERVER" -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN $t "$*"
