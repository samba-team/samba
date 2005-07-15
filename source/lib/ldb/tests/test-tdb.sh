#!/bin/sh


LDB_URL="tdbtest.ldb"
export LDB_URL

PATH=bin:$PATH
export PATH

rm -f tdbtest.ldb
rm -f tdbtest.ldb.1
rm -f tdbtest.ldb.2

if [ -z "$LDBDIR" ]; then
    LDBDIR="."
    export LDBDIR
fi

. $LDBDIR/tests/test-generic.sh

. $LDBDIR/tests/test-extended.sh

. $LDBDIR/tests/test-tdb-features.sh
