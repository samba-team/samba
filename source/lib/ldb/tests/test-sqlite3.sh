#!/bin/sh


export LDB_URL="sqlite://sqltest.ldb"

rm -f sqltest.ldb

. tests/test-generic.sh

