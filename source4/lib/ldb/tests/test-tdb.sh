#!/bin/sh


export LDB_URL="tdb://tdbtest.ldb"

rm -f tdbtest.ldb

. tests/test-generic.sh

. tests/test-extended.sh
