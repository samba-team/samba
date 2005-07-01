#!/bin/sh


export LDB_URL="tdbtest.ldb"

PATH=bin:$PATH
export PATH

rm -f tdbtest.ldb

if [ -z "$LDBDIR" ]; then
    LDBDIR="."
    export LDBDIR
fi

. $LDBDIR/tests/test-generic.sh

. $LDBDIR/tests/test-extended.sh

. $LDBDIR/tests/test-tdb-features.sh
