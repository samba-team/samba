#!/bin/sh


LDB_URL="sqlite://test.ldb"
export LDB_URL

rm -f sqltest.ldb

. $LDBDIR/tests/test-generic.sh

