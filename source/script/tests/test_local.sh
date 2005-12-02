#!/bin/sh

local_tests="LOCAL-NTLMSSP LOCAL-TALLOC LOCAL-MESSAGING LOCAL-IRPC LOCAL-BINDING LOCAL-IDTREE LOCAL-SOCKET LOCAL-PAC LOCAL-STRLIST LOCAL-SDDL"

if [ $# -lt 0 ]; then
cat <<EOF
Usage: test_local.sh
EOF
exit 1;
fi

incdir=`dirname $0`
. $incdir/test_functions.sh

# the local tests doesn't need smbd
SMBD_TEST_FIFO=""
export SMBD_TEST_FIFO

failed=0
for t in $local_tests; do
	name="$t"
	testit "$name" $VALGRIND bin/smbtorture $TORTURE_OPTIONS ncalrpc: $t "$*" || failed=`expr $failed + 1`
done

testok $0 $failed
