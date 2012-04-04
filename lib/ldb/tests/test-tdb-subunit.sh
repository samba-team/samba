#!/bin/sh

BINDIR=$1

. `dirname $0`/../../../testprogs/blackbox/subunit.sh

testit "ldb" `dirname $0`/test-tdb.sh $BINDIR
