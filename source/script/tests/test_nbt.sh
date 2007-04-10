#!/bin/sh
# test some NBT/WINS operations

incdir=`dirname $0`
. $incdir/test_functions.sh

SCRIPTDIR=../testprogs/ejs

PATH=bin:$PATH
export PATH

plantest "nmblookup -U \$SERVER \$SERVER" dc bin/nmblookup $TORTURE_OPTIONS -U \$SERVER \$SERVER
plantest "nmblookup \$SERVER" dc bin/nmblookup $TORTURE_OPTIONS \$SERVER

NBT_TESTS=`bin/smbtorture --list | grep ^NBT`

for f in $NBT_TESTS; do
    plantest "$f" dc bin/smbtorture $TORTURE_OPTIONS //\$SERVER/_none_ $f -U\$USERNAME%\$PASSWORD 
done
