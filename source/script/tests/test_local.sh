#!/bin/sh

local_tests="LOCAL-REPLACE LOCAL-TALLOC LOCAL-STRLIST"
local_tests="$local_tests LOCAL-IDTREE LOCAL-EVENT"
local_tests="$local_tests LOCAL-SOCKET LOCAL-MESSAGING LOCAL-IRPC"
local_tests="$local_tests LOCAL-NDR LOCAL-BINDING LOCAL-FILE LOCAL-REGISTRY"
local_tests="$local_tests LOCAL-SDDL LOCAL-PAC LOCAL-DBSPEED LOCAL-TDR "
local_tests="$local_tests LOCAL-NTLMSSP LOCAL-CRYPTO-MD4"
local_tests="$local_tests LOCAL-CRYPTO-MD5 LOCAL-CRYPTO-HMACMD5"
local_tests="$local_tests LOCAL-CRYPTO-SHA1 LOCAL-CRYPTO-HMACSHA1"
local_tests="$local_tests LOCAL-RESOLVE LOCAL-TORTURE"

if [ `uname` = "Linux" ]; then
    # testing against the system iconv only makes sense for our 'reference' iconv
    # behaviour
    local_tests="$local_tests LOCAL-ICONV"
fi

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
