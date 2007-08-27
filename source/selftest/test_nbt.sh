#!/bin/sh
# test some NBT/WINS operations

incdir=`dirname $0`
. $incdir/test_functions.sh

PATH=bin:$PATH
export PATH

TEST_NBT_ENVNAME=$1
if test x"$TEST_NBT_ENVNAME" = x"";then
	TEST_NBT_ENVNAME="dc"
fi

NBT_TESTS=`bin/smbtorture --list | grep "^NBT-" | xargs`

if test x"$TEST_NBT_ENVNAME" = x"dc";then
    for f in $NBT_TESTS; do
        plantest "$f:$TEST_NBT_ENVNAME" $TEST_NBT_ENVNAME bin/smbtorture $TORTURE_OPTIONS //\$SERVER/_none_ $f -U\$USERNAME%\$PASSWORD 
    done
fi
