#!/bin/sh

export LDB_URL="tdb://schema.ldb"

rm -f schema.ldb

echo "LDB_URL: $LDB_URL"

echo "Adding schema"
$VALGRIND bin/ldbadd tests/schema.ldif || exit 1

echo "Adding few test elements (no failure expected here)"
$VALGRIND bin/ldbadd tests/schema-add-test.ldif || exit 1

echo "Modifying elements (2 failures expected here)"
$VALGRIND bin/ldbmodify tests/schema-mod-test.ldif

echo "Showing modified record"
$VALGRIND bin/ldbsearch '(cn=Test)'  || exit 1

