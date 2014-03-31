#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: test_wbinfo_simple.sh <wbinfo args>
EOF
exit 1;
fi

ADDARGS="$*"

incdir=`dirname $0`/../../testprogs/blackbox
. $incdir/subunit.sh

testit "wbinfo" $VALGRIND $BINDIR/wbinfo $ADDARGS || failed=`expr $failed + 1`

testok $0 $failed
