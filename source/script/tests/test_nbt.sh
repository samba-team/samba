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

testit "nmblookup -U $SERVER $SERVER" bin/nmblookup $TORTURE_OPTIONS -U $SERVER $SERVER || failed=`expr $failed + 1`
testit "nmblookup $SERVER" bin/nmblookup $TORTURE_OPTIONS $SERVER || failed=`expr $failed + 1`

NBT_TESTS="NBT-REGISTER NBT-WINS"
NBT_TESTS="$NBT_TESTS NBT-WINSREPLICATION"
# if [ "$TORTURE_QUICK"x != "yes"x ]; then
# 	NBT_TESTS="$NBT_TESTS NBT-WINSREPLICATION-OWNED"
# fi
NBT_TESTS="$NBT_TESTS NET-API-LOOKUP NET-API-LOOKUPHOST NET-API-LOOKUPPDC"

for f in $NBT_TESTS; do
    testit "$f" bin/smbtorture $TORTURE_OPTIONS //$SERVER/_none_ $f || failed=`expr $failed + 1`
done

testok $0 $failed
