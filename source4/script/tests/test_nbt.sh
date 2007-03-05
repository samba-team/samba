#!/bin/sh
# test some NBT/WINS operations

if [ $# -lt 1 ]; then
cat <<EOF
Usage: test_nbt.sh SERVER
EOF
exit 1;
fi

SERVER="$1"

incdir=`dirname $0`
. $incdir/test_functions.sh

SCRIPTDIR=../testprogs/ejs

PATH=bin:$PATH
export PATH

testit "nmblookup -U $SERVER $SERVER" bin/nmblookup $TORTURE_OPTIONS -U $SERVER $SERVER
testit "nmblookup $SERVER" bin/nmblookup $TORTURE_OPTIONS $SERVER

NBT_TESTS="NBT-REGISTER NBT-WINS"
NBT_TESTS="$NBT_TESTS NBT-WINSREPLICATION"
# NBT_TESTS="$NBT_TESTS NBT-WINSREPLICATION-OWNED"
NBT_TESTS="$NBT_TESTS NET-API-LOOKUP NET-API-LOOKUPHOST NET-API-LOOKUPPDC"

for f in $NBT_TESTS; do
    testit "$f" bin/smbtorture $TORTURE_OPTIONS //$SERVER/_none_ $f
done

testok $0 $failed
