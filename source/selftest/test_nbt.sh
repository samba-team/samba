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

plantest "nmblookup -U \$SERVER_IP \$SERVER" $TEST_NBT_ENVNAME bin/nmblookup $TORTURE_OPTIONS -U \$SERVER_IP \$SERVER
plantest "nmblookup -U \$SERVER_IP \$NETBIOSNAME" $TEST_NBT_ENVNAME bin/nmblookup $TORTURE_OPTIONS -U \$SERVER_IP \$NETBIOSNAME
plantest "nmblookup -U \$SERVER_IP \$NETBIOSALIAS" $TEST_NBT_ENVNAME bin/nmblookup $TORTURE_OPTIONS -U \$SERVER_IP \$NETBIOSALIAS
plantest "nmblookup \$SERVER" $TEST_NBT_ENVNAME bin/nmblookup $TORTURE_OPTIONS \$SERVER
plantest "nmblookup \$NETBIOSNAME" $TEST_NBT_ENVNAME bin/nmblookup $TORTURE_OPTIONS \$NETBIOSNAME
plantest "nmblookup \$NETBIOSALIAS" $TEST_NBT_ENVNAME bin/nmblookup $TORTURE_OPTIONS \$NETBIOSALIAS

NBT_TESTS=`bin/smbtorture --list | grep "^NBT-" | xargs`

if test x"$TEST_NBT_ENVNAME" = x"dc";then
    for f in $NBT_TESTS; do
        plantest "$f:$TEST_NBT_ENVNAME" $TEST_NBT_ENVNAME bin/smbtorture $TORTURE_OPTIONS //\$SERVER/_none_ $f -U\$USERNAME%\$PASSWORD 
    done
fi
