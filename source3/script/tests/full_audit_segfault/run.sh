#!/bin/sh
if [ $# -lt 1 ]; then
	cat <<EOF
Usage: run.sh VFSTEST
EOF
	exit 1
fi

TALLOC_FILL_FREE=0
export TALLOC_FILL_FREE

TESTBASE="$(dirname $0)"
VFSTEST="$VALGRIND $1"
shift 1
ADDARGS="$*"

incdir=$(dirname $0)/../../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

testit "vfstest" "$VFSTEST" -f "$TESTBASE/vfstest.cmd" "$ADDARGS" ||
	failed=$(expr $failed + 1)

exit $failed
