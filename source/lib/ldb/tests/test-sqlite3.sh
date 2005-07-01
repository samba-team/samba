#!/bin/sh


export LDB_URL="sqlite:///var/tmp/test.ldb"

rm -f sqltest.ldb

. $LDBDIR/tests/test-generic.sh

