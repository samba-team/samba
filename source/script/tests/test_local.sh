#!/bin/sh

local_tests="LOCAL-NTLMSSP LOCAL-ICONV LOCAL-TALLOC LOCAL-MESSAGING LOCAL-IRPC LOCAL-BINDING LOCAL-IDTREE LOCAL-SOCKET"

if [ $# -lt 0 ]; then
cat <<EOF
Usage: test_local.sh
EOF
exit 1;
fi

if [ -z "$VALGRIND" ]; then
    export MALLOC_CHECK_=2
fi

incdir=`dirname $0`
. $incdir/test_functions.sh

failed=0
for t in $local_tests; do
	name="$t"
	testit "$name" $VALGRIND bin/smbtorture ncalrpc: $t "$*" || failed=`expr $failed + 1`
done

testok $0 $failed
