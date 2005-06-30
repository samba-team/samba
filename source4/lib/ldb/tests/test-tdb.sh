#!/bin/sh


export LDB_URL="tdbtest.ldb"

rm -f tdbtest.ldb

. tests/test-generic.sh

. tests/test-extended.sh

. tests/test-tdb-features.sh
