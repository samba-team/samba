#!/bin/sh
# test some NBT/WINS operations

if [ $# -lt 1 ]; then
cat <<EOF
Usage: test_nbt.sh SERVER
EOF
exit 1;
fi

SERVER="$1"
USERNAME="$2"
PASSWORD="$3"

incdir=`dirname $0`
. $incdir/test_functions.sh

SCRIPTDIR=../testprogs/ejs

PATH=bin:$PATH
export PATH

testit "nmblookup -U $SERVER $SERVER" bin/nmblookup $TORTURE_OPTIONS -U $SERVER $SERVER
testit "nmblookup $SERVER" bin/nmblookup $TORTURE_OPTIONS $SERVER

NBT_TESTS=`bin/smbtorture --list | grep ^NBT`

for f in $NBT_TESTS; do
    testit "$f" bin/smbtorture $TORTURE_OPTIONS //$SERVER/_none_ $f -U$USERNAME%$PASSWORD 
done

testok $0 $failed
