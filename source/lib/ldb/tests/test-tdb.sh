#!/bin/sh

if [ -n "$TEST_DATA_PREFIX" ]; then
	LDB_URL="$TEST_DATA_PREFIX/tdbtest.ldb"
else
	LDB_URL="tdbtest.ldb"
fi
export LDB_URL

PATH=bin:$PATH
export PATH

rm -f $LDB_URL*

if [ -z "$LDBDIR" ]; then
    LDBDIR="."
    export LDBDIR
fi

. $LDBDIR/tests/test-generic.sh

. $LDBDIR/tests/test-extended.sh

. $LDBDIR/tests/test-tdb-features.sh
