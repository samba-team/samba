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

for f in NBT-REGISTER NBT-WINS; do
    testit "$f" bin/smbtorture $TORTURE_OPTIONS //$SERVER/_none_ $f || failed=`expr $failed + 1`
done

for f in NBT-WINSREPLICATION-QUICK; do
    testit "$f" bin/smbtorture $TORTURE_OPTIONS $WREPL_TORTURE_OPTIONS //$SERVER/_none_ $f || failed=`expr $failed + 1`
done

testok $0 $failed
