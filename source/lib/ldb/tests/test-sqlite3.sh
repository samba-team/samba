#!/bin/sh


LDB_URL="sqlite://sqltest.ldb"
export LDB_URL

PATH=bin:$PATH
export PATH

rm -f sqltest.ldb

if [ -z "$LDBDIR" ]; then
    LDBDIR="."
    export LDBDIR
fi

. $LDBDIR/tests/test-generic.sh

#. $LDBDIR/tests/test-extended.sh

#. $LDBDIR/tests/test-tdb-features.sh

